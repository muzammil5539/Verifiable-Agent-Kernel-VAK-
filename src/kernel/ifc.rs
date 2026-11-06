//! Information-flow labels (the Labels stage; `docs/adr/0014`).
//!
//! Indirect prompt injection means any tool result can carry instructions.
//! Detecting them is a heuristic. What the kernel can enforce is *where data
//! came from*: every result it returns carries a [`Label`], and policies can
//! refuse a consequential call whose arguments may have come from somewhere
//! untrusted (`docs/architecture-v2.md` §4.4):
//!
//! ```yaml
//! - id: "no-untrusted-email"
//!   effect: "forbid"
//!   principal: "*"
//!   action: "*"
//!   resource: "Tool::\"email:send\""
//!   conditions:
//!     - "context.args_integrity == \"untrusted\""
//! ```
//!
//! A label has three parts:
//!
//! - [`Integrity`]: `trusted` or `untrusted`. It records whether anything
//!   untrusted went into the value.
//! - [`Readers`]: who may receive the value. Either `public`, or only the
//!   readers named.
//! - Sources: the tools and skills it came from.
//!
//! Labels only rise. Combining two values joins their labels ([`Label::join`]):
//! untrusted wins, readers narrow to those both allow, and sources add up.
//!
//! # What the kernel tracks
//!
//! With `policy.labels.enabled`, the kernel keeps a *context label* for each
//! agent: the join of every result it has returned to the agent and every
//! label the agent has declared. The kernel can't see which value an
//! argument came from, so it assumes each argument may depend on all of
//! them. A call's arguments get the agent's context label. That is coarse,
//! and it is sound: once an agent has read something untrusted, everything
//! it does afterwards is treated as possibly influenced by it.
//!
//! - **Per agent, not per session.** A new session doesn't clear the label.
//!   The MCP gateway and `VakRuntime::execute_tool_call` open a session per
//!   call, so a per-session label would never accumulate there.
//! - **Declared labels only raise.** An agent can declare that its arguments
//!   carry a label, with [`Kernel::execute_labeled`](super::Kernel::execute_labeled),
//!   for data the kernel never saw. The declared label is joined into the
//!   agent's context, never substituted for it.
//! - **What a result gets.** The tool's source label from
//!   `policy.labels.sources`, joined with the label of its arguments. A
//!   tool's output can depend on its input.
//! - **Unlisted tools are untrusted.** A tool with no source label is
//!   untrusted, unless it is a built-in. Built-ins compute only from their
//!   arguments, and their results carry their arguments' label. Readers
//!   default to `public`.
//!
//! The guarantee is `Enforced` for propagation inside the kernel. It is only
//! as good as the agent framework's hygiene outside it:
//!
//! - **Declared labels.** Data the kernel didn't return must be declared.
//! - **Agent identity.** Each context needs its own agent ID, and an agent
//!   must not be able to choose a fresh one.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::guard::{tool_pattern_matches, validate_tool_pattern};

/// The most sources, and the most readers, a label declared with
/// [`Kernel::execute_labeled`](super::Kernel::execute_labeled) may name. A
/// declared label is kept in the agent's context and recorded in the audit
/// log, so its size is bounded.
pub const MAX_DECLARED: usize = 256;

/// Whether anything untrusted went into a value.
///
/// Ordered `Trusted < Untrusted`, so the join of two levels is the greater.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Integrity {
    /// Only trusted data went into the value: the agent's own input, and
    /// results of tools labelled trusted.
    #[default]
    Trusted,
    /// Something untrusted may have gone into the value.
    Untrusted,
}

impl Integrity {
    /// The level's name as configuration and policies spell it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Integrity::Trusted => "trusted",
            Integrity::Untrusted => "untrusted",
        }
    }
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who may receive a value.
///
/// Configuration and audit records spell it `public`, or as a list of
/// readers. The empty list means no one: what is left when two values with
/// no reader in common are combined.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum Readers {
    /// Anyone.
    #[default]
    Public,
    /// Only these readers.
    Only(BTreeSet<String>),
}

impl Readers {
    /// Only `readers`.
    #[must_use]
    pub fn only<I, S>(readers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Readers::Only(readers.into_iter().map(Into::into).collect())
    }

    /// Whether anyone may receive the value.
    #[must_use]
    pub fn is_public(&self) -> bool {
        matches!(self, Readers::Public)
    }

    /// Whether `reader` may receive the value.
    #[must_use]
    pub fn allows(&self, reader: &str) -> bool {
        match self {
            Readers::Public => true,
            Readers::Only(readers) => readers.contains(reader),
        }
    }

    /// The readers both allow.
    #[must_use]
    pub fn join(&self, other: &Readers) -> Readers {
        match (self, other) {
            (Readers::Public, other) | (other, Readers::Public) => other.clone(),
            (Readers::Only(a), Readers::Only(b)) => {
                Readers::Only(a.intersection(b).cloned().collect())
            }
        }
    }

    /// Whether every reader `other` allows is also allowed here: data may
    /// flow from here to there without letting anyone new read it.
    #[must_use]
    pub fn covers(&self, other: &Readers) -> bool {
        match (self, other) {
            (Readers::Public, _) => true,
            (Readers::Only(_), Readers::Public) => false,
            (Readers::Only(a), Readers::Only(b)) => b.is_subset(a),
        }
    }
}

const PUBLIC: &str = "public";

impl Serialize for Readers {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Readers::Public => serializer.serialize_str(PUBLIC),
            Readers::Only(readers) => readers.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Readers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Word(String),
            List(BTreeSet<String>),
        }
        match Repr::deserialize(deserializer)? {
            Repr::Word(word) if word == PUBLIC => Ok(Readers::Public),
            Repr::Word(word) => Err(serde::de::Error::custom(format!(
                "readers must be \"public\" or a list of readers, not \"{word}\""
            ))),
            Repr::List(readers) => Ok(Readers::Only(readers)),
        }
    }
}

/// Where a value came from.
///
/// Spelled `user`, `tool:<name>` or `skill:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum Source {
    /// The agent's own input, such as the user's request.
    User,
    /// A built-in tool or a host tool handler.
    Tool(String),
    /// A WASM skill.
    Skill(String),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::User => f.write_str("user"),
            Source::Tool(name) => write!(f, "tool:{name}"),
            Source::Skill(name) => write!(f, "skill:{name}"),
        }
    }
}

impl From<Source> for String {
    fn from(source: Source) -> Self {
        source.to_string()
    }
}

impl TryFrom<String> for Source {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value == "user" {
            return Ok(Source::User);
        }
        if let Some(name) = value.strip_prefix("tool:") {
            return Ok(Source::Tool(name.to_string()));
        }
        if let Some(name) = value.strip_prefix("skill:") {
            return Ok(Source::Skill(name.to_string()));
        }
        Err(format!(
            "a source is \"user\", \"tool:<name>\" or \"skill:<name>\", not \"{value}\""
        ))
    }
}

/// A value's information-flow label: its integrity, who may read it, and
/// where it came from.
///
/// The default label is the lowest: trusted, public, from nowhere. Joining
/// it with any label leaves that label unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Label {
    /// Whether anything untrusted went into the value.
    pub integrity: Integrity,
    /// Who may receive it.
    pub readers: Readers,
    /// The tools and skills it came from.
    #[serde(default)]
    pub sources: BTreeSet<Source>,
}

impl Label {
    /// Trusted, public, from nowhere: the lowest label.
    #[must_use]
    pub fn trusted() -> Self {
        Self::default()
    }

    /// Untrusted data from `source`, readable by anyone.
    #[must_use]
    pub fn untrusted(source: Source) -> Self {
        Self {
            integrity: Integrity::Untrusted,
            readers: Readers::Public,
            sources: BTreeSet::from([source]),
        }
    }

    /// The same label with its integrity at least `integrity`.
    #[must_use]
    pub fn with_integrity(mut self, integrity: Integrity) -> Self {
        self.integrity = self.integrity.max(integrity);
        self
    }

    /// The same label, readable only by readers both it and `readers` allow.
    #[must_use]
    pub fn with_readers(mut self, readers: Readers) -> Self {
        self.readers = self.readers.join(&readers);
        self
    }

    /// The same label, with `source` among its sources.
    #[must_use]
    pub fn with_source(mut self, source: Source) -> Self {
        self.sources.insert(source);
        self
    }

    /// Whether only trusted data went into the value.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        self.integrity == Integrity::Trusted
    }

    /// The label of a value computed from values labelled `self` and
    /// `other`: untrusted if either is, readable only by readers both allow,
    /// from the sources of both.
    #[must_use]
    pub fn join(&self, other: &Label) -> Label {
        Label {
            integrity: self.integrity.max(other.integrity),
            readers: self.readers.join(&other.readers),
            sources: self.sources.union(&other.sources).cloned().collect(),
        }
    }

    /// Raises this label in place to its join with `other`.
    pub fn raise(&mut self, other: &Label) {
        *self = self.join(other);
    }

    /// Whether `other` is at least as restrictive as this label in every
    /// part, so that `self.join(other) == *other`.
    #[must_use]
    pub fn flows_to(&self, other: &Label) -> bool {
        self.integrity <= other.integrity
            && self.readers.covers(&other.readers)
            && self.sources.is_subset(&other.sources)
    }
}

/// A value with its [`Label`].
///
/// The helper in-process agents use to keep a label with the data it
/// describes. Labels travel with values: deriving one value from another
/// with [`Labeled::map`] keeps the label, and combining two with
/// [`Labeled::zip`] joins them. To use a labelled value as a tool call's
/// arguments, map it into the request and pass it to
/// [`Kernel::execute_labeled`](super::Kernel::execute_labeled):
///
/// ```rust
/// use vak::kernel::ifc::{Label, Labeled, Source};
/// use vak::kernel::types::ToolRequest;
///
/// let page = Labeled::new(
///     serde_json::json!({"body": "text fetched outside the kernel"}),
///     Label::untrusted(Source::Tool("browser".into())),
/// );
/// let request = page.map(|args| ToolRequest::new("summarize", args));
/// assert!(!request.label().is_trusted());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Labeled<T> {
    value: T,
    label: Label,
}

impl<T> Labeled<T> {
    /// `value`, labelled `label`.
    #[must_use]
    pub fn new(value: T, label: Label) -> Self {
        Self { value, label }
    }

    /// `value` with the lowest label: it adds nothing to what it's combined
    /// with.
    #[must_use]
    pub fn unlabeled(value: T) -> Self {
        Self::new(value, Label::trusted())
    }

    /// The value.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Its label.
    #[must_use]
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// The value, without its label.
    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }

    /// The value and its label.
    #[must_use]
    pub fn into_parts(self) -> (T, Label) {
        (self.value, self.label)
    }

    /// A value computed from this one alone. It keeps this label.
    #[must_use]
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Labeled<U> {
        Labeled {
            value: f(self.value),
            label: self.label,
        }
    }

    /// This value and `other` together, labelled with the join of both
    /// labels.
    #[must_use]
    pub fn zip<U>(self, other: Labeled<U>) -> Labeled<(T, U)> {
        Labeled {
            label: self.label.join(&other.label),
            value: (self.value, other.value),
        }
    }

    /// The same value, with its label raised to its join with `label`.
    #[must_use]
    pub fn raised(mut self, label: &Label) -> Self {
        self.label.raise(label);
        self
    }
}

/// The source label configured for a tool's results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLabel {
    /// Whether the tool's results are trusted.
    pub integrity: Integrity,
    /// Who may receive them. `public` unless set.
    #[serde(default)]
    pub readers: Readers,
}

/// `policy.labels`: information-flow labels (`docs/adr/0014`).
///
/// ```yaml
/// policy:
///   labels:
///     enabled: true
///     sources:
///       web_fetch: { integrity: untrusted }
///       "crm:*": { integrity: trusted, readers: [sales] }
///     external: ["email:send", "http:post"]
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelConfig {
    /// Whether the kernel tracks labels and hands them to policies. Off by
    /// default; nothing below applies while it is off.
    #[serde(default)]
    pub enabled: bool,
    /// The label on each tool's results, by tool-name pattern (`*`,
    /// `prefix*`, `*suffix` or an exact name). Where patterns overlap, their
    /// labels are joined. A tool no pattern matches is untrusted, unless it
    /// is a built-in.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sources: BTreeMap<String, SourceLabel>,
    /// Tools that send data outside, by the same patterns. Policies read
    /// this as `resource.external`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external: Vec<String>,
}

/// Which kind of tool produced a result, for its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// One of the kernel's built-in tools.
    Builtin,
    /// A host tool handler.
    Handler,
    /// A WASM skill.
    Skill,
}

impl LabelConfig {
    /// Whether this is the default configuration, so it can be left out
    /// when serialized.
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Whether `tool` sends data outside (`resource.external`).
    #[must_use]
    pub fn is_external(&self, tool: &str) -> bool {
        self.external
            .iter()
            .any(|pattern| tool_pattern_matches(pattern, tool))
    }

    /// The label `tool`'s own contribution gives its results, before its
    /// arguments' label is joined in.
    #[must_use]
    pub(crate) fn source_label(&self, tool: &str, origin: Origin) -> Label {
        let source = match origin {
            Origin::Skill => Source::Skill(tool.to_string()),
            Origin::Builtin | Origin::Handler => Source::Tool(tool.to_string()),
        };
        let mut matching = self
            .sources
            .iter()
            .filter(|(pattern, _)| tool_pattern_matches(pattern, tool))
            .map(|(_, label)| label)
            .peekable();
        let mut label = Label::trusted().with_source(source);
        if matching.peek().is_none() {
            if origin != Origin::Builtin {
                label = label.with_integrity(Integrity::Untrusted);
            }
            return label;
        }
        for configured in matching {
            label = label
                .with_integrity(configured.integrity)
                .with_readers(configured.readers.clone());
        }
        label
    }

    /// Checks the configuration.
    ///
    /// # Errors
    ///
    /// Returns a description of the problem: a tool pattern the matcher
    /// can't honour, or sources or external tools set while labels are off,
    /// where nothing would ever apply them.
    pub fn validate(&self) -> Result<(), String> {
        for pattern in self.sources.keys().chain(self.external.iter()) {
            validate_tool_pattern(pattern)?;
        }
        if !self.enabled && (!self.sources.is_empty() || !self.external.is_empty()) {
            return Err(
                "sources or external tools are set, but enabled is false, so nothing would apply them"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> Source {
        Source::Tool(name.to_string())
    }

    fn sample_labels() -> Vec<Label> {
        vec![
            Label::trusted(),
            Label::untrusted(tool("web")),
            Label::trusted().with_readers(Readers::only(["alice", "bob"])),
            Label::trusted()
                .with_readers(Readers::only(["bob", "carol"]))
                .with_source(Source::User),
            Label::untrusted(Source::Skill("s".into())).with_readers(Readers::only(["alice"])),
            Label::trusted().with_readers(Readers::only(Vec::<String>::new())),
        ]
    }

    #[test]
    fn test_join_is_a_lattice_join() {
        let labels = sample_labels();
        for a in &labels {
            assert_eq!(a.join(a), *a, "idempotent");
            assert_eq!(a.join(&Label::trusted()), *a, "the default is the bottom");
            for b in &labels {
                assert_eq!(a.join(b), b.join(a), "commutative");
                assert!(a.flows_to(&a.join(b)), "an upper bound of its left side");
                assert!(b.flows_to(&a.join(b)), "an upper bound of its right side");
                for c in &labels {
                    assert_eq!(a.join(b).join(c), a.join(&b.join(c)), "associative");
                }
            }
        }
    }

    #[test]
    fn test_untrusted_wins_and_readers_narrow() {
        let joined = Label::trusted()
            .with_readers(Readers::only(["alice", "bob"]))
            .join(&Label::untrusted(tool("web")).with_readers(Readers::only(["bob", "carol"])));
        assert_eq!(joined.integrity, Integrity::Untrusted);
        assert_eq!(joined.readers, Readers::only(["bob"]));
        assert!(joined.readers.allows("bob"));
        assert!(!joined.readers.allows("alice"));
        assert_eq!(joined.sources, BTreeSet::from([tool("web")]));

        // Disjoint readers leave no one, which is not the same as public.
        let nobody = Readers::only(["alice"]).join(&Readers::only(["bob"]));
        assert_eq!(nobody, Readers::Only(BTreeSet::new()));
        assert!(!nobody.is_public());
        assert!(!nobody.allows("alice"));
    }

    #[test]
    fn test_builders_only_raise() {
        let untrusted = Label::untrusted(tool("web"));
        assert_eq!(
            untrusted
                .clone()
                .with_integrity(Integrity::Trusted)
                .integrity,
            Integrity::Untrusted
        );
        let narrow = Label::trusted().with_readers(Readers::only(["alice"]));
        assert_eq!(
            narrow.clone().with_readers(Readers::Public).readers,
            Readers::only(["alice"])
        );
        let mut raised = Label::trusted();
        raised.raise(&untrusted);
        assert!(!raised.is_trusted());
    }

    #[test]
    fn test_labels_round_trip_through_json() {
        for label in sample_labels() {
            let json = serde_json::to_string(&label).unwrap();
            let back: Label = serde_json::from_str(&json).unwrap();
            assert_eq!(back, label, "{json}");
            // The audit log hashes a label's JSON, so a read-back label
            // must serialize to the same bytes.
            assert_eq!(serde_json::to_string(&back).unwrap(), json);
        }
        let json = serde_json::to_value(
            Label::untrusted(tool("web")).with_readers(Readers::only(["alice"])),
        )
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "integrity": "untrusted",
                "readers": ["alice"],
                "sources": ["tool:web"],
            })
        );
        assert_eq!(
            serde_json::to_value(Label::trusted()).unwrap()["readers"],
            "public"
        );
    }

    #[test]
    fn test_malformed_readers_and_sources_are_refused() {
        assert!(serde_json::from_str::<Readers>("\"everyone\"").is_err());
        assert_eq!(
            serde_json::from_str::<Readers>("[\"public\"]").unwrap(),
            Readers::only(["public"]),
            "a reader named public is a reader, not the word"
        );
        assert!(serde_json::from_str::<Source>("\"web\"").is_err());
        assert_eq!(
            serde_json::from_str::<Source>("\"skill:calc\"").unwrap(),
            Source::Skill("calc".into())
        );
    }

    #[test]
    fn test_labeled_keeps_and_joins_labels() {
        let a = Labeled::new(1, Label::untrusted(tool("web")));
        let b = Labeled::new(2, Label::trusted().with_readers(Readers::only(["alice"])));
        let sum = a.clone().zip(b).map(|(x, y)| x + y);
        assert_eq!(*sum.value(), 3);
        assert!(!sum.label().is_trusted());
        assert_eq!(sum.label().readers, Readers::only(["alice"]));
        assert_eq!(a.clone().map(|x| x * 10).label(), a.label());
        let raised = Labeled::unlabeled("x").raised(a.label());
        assert_eq!(raised.label(), a.label());
        assert_eq!(raised.into_parts(), ("x", a.label().clone()));
    }

    #[test]
    fn test_unlisted_tools_are_untrusted_except_builtins() {
        let config = LabelConfig {
            enabled: true,
            ..LabelConfig::default()
        };
        assert!(config.source_label("echo", Origin::Builtin).is_trusted());
        assert!(!config.source_label("fetch", Origin::Handler).is_trusted());
        let skill = config.source_label("calc", Origin::Skill);
        assert!(!skill.is_trusted());
        assert_eq!(
            skill.sources,
            BTreeSet::from([Source::Skill("calc".into())])
        );
    }

    #[test]
    fn test_overlapping_sources_join() {
        let config: LabelConfig = serde_yaml::from_str(
            r#"
enabled: true
sources:
  "crm:*": { integrity: trusted, readers: [sales, support] }
  "*:export": { integrity: untrusted, readers: [sales] }
  calculator: { integrity: untrusted }
external: ["email:*"]
"#,
        )
        .unwrap();
        config.validate().unwrap();
        let both = config.source_label("crm:export", Origin::Handler);
        assert_eq!(both.integrity, Integrity::Untrusted);
        assert_eq!(both.readers, Readers::only(["sales"]));
        let crm = config.source_label("crm:read", Origin::Handler);
        assert!(crm.is_trusted(), "a configured source can be trusted");
        assert_eq!(crm.readers, Readers::only(["sales", "support"]));
        assert!(
            !config
                .source_label("calculator", Origin::Builtin)
                .is_trusted(),
            "configuration can distrust a built-in"
        );
        assert!(config.is_external("email:send"));
        assert!(!config.is_external("crm:read"));
    }

    #[test]
    fn test_config_that_could_never_apply_is_refused() {
        let off_with_sources: LabelConfig =
            serde_yaml::from_str("sources: { web: { integrity: untrusted } }").unwrap();
        assert!(off_with_sources.validate().is_err());
        let off_with_external: LabelConfig =
            serde_yaml::from_str("external: [\"email:send\"]").unwrap();
        assert!(off_with_external.validate().is_err());
        let bad_pattern: LabelConfig =
            serde_yaml::from_str("enabled: true\nexternal: [\"e*mail\"]").unwrap();
        assert!(bad_pattern.validate().is_err());
        assert!(serde_yaml::from_str::<LabelConfig>("enabled: true\nsorces: {}").is_err());
        assert!(LabelConfig::default().validate().is_ok());
        assert!(LabelConfig::default().is_default());
    }
}
