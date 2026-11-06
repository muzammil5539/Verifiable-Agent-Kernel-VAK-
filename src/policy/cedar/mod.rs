//! Cedar policies, evaluated by the `cedar-policy` crate (docs/adr/0008).
//!
//! [`CedarPolicySet`] loads a schema and `.cedar` policy files, validates the
//! policies against the schema in strict mode, and decides tool calls. The
//! kernel uses it through [`CedarPolicy`](crate::kernel::CedarPolicy), its
//! `PolicyDecisionPoint` adapter.
//!
//! Every call is asked about as
//!
//! | | |
//! |---|---|
//! | principal | `Vak::Agent::"<agent id>"`, with `internal`, `name` and the record's attributes |
//! | action | `Vak::Action::"<tool>"` if the schema declares it, else `Vak::Action::"call"` |
//! | resource | `Vak::Tool::"<tool>"`, with `restricted` and `builtin` |
//! | context | `{ session, arguments }`; `arguments` is `{}` for the generic `call` |
//!
//! With `policy.labels.enabled` (docs/adr/0016), the context also carries
//! `labels`, the information-flow label of the call's arguments, and the tool
//! carries `external`. A schema declares both, required, or neither.
//!
//! The schema is the contract for all of it. A policy that doesn't validate
//! against the schema fails the load; a request that doesn't match it is
//! denied. So is a request on which any policy fails to evaluate: Cedar
//! itself skips a policy that errors, which would let a request through a
//! `forbid` that overflowed.
//!
//! With the `cedar-analysis` feature, [`analysis`] proves properties of a
//! whole policy set with SymCC (docs/adr/0009).

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use cedar_policy::{
    AuthorizationError, Authorizer, Context, Decision, Entities, EntityUid, PolicyId, PolicySet,
    Request, Schema, ValidationMode, Validator,
};
use serde_json::{json, Value};
use thiserror::Error;

use crate::kernel::ifc::{Label, Readers};

#[cfg(feature = "cedar-analysis")]
pub mod analysis;

/// The kernel's Cedar schema, used unless `policy.cedar_schema` names
/// another. Also shipped as `policies/cedar/vak.cedarschema`.
pub const VAK_SCHEMA: &str = include_str!("../../../policies/cedar/vak.cedarschema");

/// The namespace of every entity and action the kernel supplies.
pub const NAMESPACE: &str = "Vak";

/// The action every tool call is decided as when the schema declares no
/// action for the tool itself.
pub const CALL_ACTION: &str = "call";

/// Why a schema or policy set couldn't be loaded.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum CedarPolicyError {
    /// A file couldn't be read.
    #[error("{path}: {message}")]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// What went wrong.
        message: String,
    },

    /// The schema doesn't parse.
    #[error("Cedar schema: {0}")]
    Schema(String),

    /// The schema doesn't accept the entities and context the kernel
    /// supplies, so no request could be decided.
    #[error("the Cedar schema doesn't accept what the kernel supplies: {0}")]
    Contract(String),

    /// A policy file doesn't parse.
    #[error("{origin}: {message}")]
    Parse {
        /// The file the policies came from.
        origin: String,
        /// What went wrong.
        message: String,
    },

    /// A policy file contains templates, which this adapter doesn't link.
    #[error("{origin}: policy templates are not supported")]
    Template {
        /// The file the template came from.
        origin: String,
    },

    /// A policy carries `@property`: it states a property to prove
    /// (`analysis`), and loading it as a policy would grant what it allows.
    #[error("{origin}: policy {id} is a property (@property), not a policy")]
    PropertyAsPolicy {
        /// The file it came from.
        origin: String,
        /// Its id.
        id: String,
    },

    /// Two policies have the same id. Ids name policies in audit records,
    /// so they must be unique.
    #[error("policy id `{0}` is used more than once")]
    DuplicateId(String),

    /// No policies were found.
    #[error("no Cedar policies found in {0}")]
    Empty(String),

    /// The policies don't validate against the schema.
    #[error("Cedar policies don't validate against the schema: {}", .0.join("; "))]
    Invalid(Vec<String>),
}

/// What the kernel knows about one tool call, in the terms of the schema.
#[derive(Debug, Clone, Copy)]
pub struct CedarRequest<'a> {
    /// The agent's id: the principal's entity id.
    pub agent_id: &'a str,
    /// The agent record's name.
    pub agent_name: &'a str,
    /// The agent record's `internal` flag.
    pub internal: bool,
    /// The agent record's attributes. Each must be declared on `Vak::Agent`.
    pub attributes: &'a HashMap<String, Value>,
    /// The tool's name: the resource's entity id, and the action's if the
    /// schema declares one for it.
    pub tool: &'a str,
    /// The tool is in `security.blocked_tools`.
    pub restricted: bool,
    /// The tool is a kernel built-in.
    pub builtin: bool,
    /// The session the call was made in, or `""`.
    pub session: &'a str,
    /// The call's arguments. Passed only to an action declared for the tool.
    pub arguments: &'a Value,
    /// The information-flow label of the call's arguments (docs/adr/0016).
    /// Supplied as `context.labels`, together with the tool's `external`
    /// attribute; `None` supplies neither.
    pub labels: Option<&'a Label>,
    /// The tool is in `policy.labels.external`. Supplied only with `labels`.
    pub external: bool,
}

/// How Cedar decided a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CedarDecision {
    /// At least one policy permits the call and none forbids it.
    Allow {
        /// The permitting policies.
        policies: Vec<String>,
    },
    /// At least one policy forbids the call.
    Forbid {
        /// The forbidding policies.
        policies: Vec<String>,
    },
    /// No policy permits the call: Cedar's default deny.
    NotPermitted,
    /// The call couldn't be decided: it doesn't match the schema, or a
    /// policy failed to evaluate on it. Treated as a denial.
    Error {
        /// What went wrong.
        reason: String,
        /// The policies that failed, if any.
        policies: Vec<String>,
    },
}

impl CedarDecision {
    /// Whether the call may proceed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

/// A validated Cedar schema and policy set.
#[derive(Debug, Clone)]
pub struct CedarPolicySet {
    schema: Schema,
    /// The schema's source, to tell whether two sets share a schema.
    #[cfg(feature = "cedar-analysis")]
    schema_text: String,
    policies: PolicySet,
    /// Tools the schema declares an action for (`Vak::Action::"<tool>"`).
    tool_actions: BTreeSet<String>,
    /// Policy ids, for reporting.
    ids: BTreeSet<String>,
    /// The schema declares `context.labels` and `Tool.external`, so every
    /// call must carry them (docs/adr/0016).
    labelled: bool,
}

impl CedarPolicySet {
    /// Loads the schema at `schema` (or [`VAK_SCHEMA`]) and the policies in
    /// `paths`. A path that is a directory contributes every `*.cedar` file
    /// directly in it.
    ///
    /// # Errors
    ///
    /// Any [`CedarPolicyError`]: a file can't be read, the schema or a policy
    /// doesn't parse, ids collide, no policies are found, or the policies
    /// don't validate against the schema.
    pub fn load(schema: Option<&Path>, paths: &[PathBuf]) -> Result<Self, CedarPolicyError> {
        let schema_src = match schema {
            Some(path) => read(path)?,
            None => VAK_SCHEMA.to_string(),
        };

        let sources = read_sources(paths)?;
        Self::from_sources(&schema_src, &sources)
    }

    /// Builds a policy set from a schema and `(origin, policies)` pairs,
    /// where `origin` names the source in errors and default policy ids.
    ///
    /// A policy's id is its `@id("…")` annotation, or `<origin>/policyN`
    /// without one.
    ///
    /// # Errors
    ///
    /// As [`CedarPolicySet::load`], less the I/O errors.
    pub fn from_sources(
        schema: &str,
        sources: &[(String, String)],
    ) -> Result<Self, CedarPolicyError> {
        let schema_source = schema;
        #[cfg(feature = "cedar-analysis")]
        let schema_text = schema.to_string();
        let (schema, warnings) = Schema::from_cedarschema_str(schema)
            .map_err(|e| CedarPolicyError::Schema(error_chain(&e)))?;
        for warning in warnings {
            tracing::warn!(%warning, "Cedar schema warning");
        }

        let mut policies = PolicySet::new();
        let mut ids = BTreeSet::new();
        for (origin, text) in sources {
            let parsed = PolicySet::from_str(text).map_err(|e| CedarPolicyError::Parse {
                origin: origin.clone(),
                message: error_chain(&e),
            })?;
            if parsed.templates().next().is_some() {
                return Err(CedarPolicyError::Template {
                    origin: origin.clone(),
                });
            }
            for policy in parsed.policies() {
                if policy.annotation("property").is_some() {
                    return Err(CedarPolicyError::PropertyAsPolicy {
                        origin: origin.clone(),
                        id: policy.id().to_string(),
                    });
                }
                let id = policy
                    .annotation("id")
                    .map_or_else(|| format!("{origin}/{}", policy.id()), str::to_string);
                if !ids.insert(id.clone()) {
                    return Err(CedarPolicyError::DuplicateId(id));
                }
                policies
                    .add(policy.new_id(PolicyId::new(&id)))
                    .map_err(|e| CedarPolicyError::Parse {
                        origin: origin.clone(),
                        message: error_chain(&e),
                    })?;
            }
        }
        if ids.is_empty() {
            let where_ = sources
                .iter()
                .map(|(origin, _)| origin.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(CedarPolicyError::Empty(where_));
        }

        let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !validation.validation_passed() {
            return Err(CedarPolicyError::Invalid(
                validation
                    .validation_errors()
                    .map(|e| e.to_string())
                    .collect(),
            ));
        }
        for warning in validation.validation_warnings() {
            tracing::warn!(%warning, "Cedar policy warning");
        }

        let action_type = format!("{NAMESPACE}::Action");
        let tool_actions = schema
            .actions()
            .filter(|uid| uid.type_name().to_string() == action_type)
            .map(|uid| uid.id().unescaped().to_string())
            .filter(|name| name != CALL_ACTION)
            .collect();

        let mut set = Self {
            schema,
            #[cfg(feature = "cedar-analysis")]
            schema_text,
            policies,
            tool_actions,
            ids,
            labelled: false,
        };
        set.labelled = set.check_contract(schema_source)?;
        Ok(set)
    }

    /// The ids of the loaded policies.
    pub fn policy_ids(&self) -> impl Iterator<Item = &str> {
        self.ids.iter().map(String::as_str)
    }

    /// The tools the schema declares their own action for.
    pub fn tool_actions(&self) -> impl Iterator<Item = &str> {
        self.tool_actions.iter().map(String::as_str)
    }

    /// Whether the schema declares `context.labels` and `Tool.external`, so
    /// that every call must carry a label (docs/adr/0016). The kernel's
    /// `policy.labels.enabled` must agree, or every call is denied.
    #[must_use]
    pub fn takes_labels(&self) -> bool {
        self.labelled
    }

    /// Decides one call.
    #[must_use]
    pub fn authorize(&self, request: &CedarRequest<'_>) -> CedarDecision {
        let (request, entities) = match self.build(request) {
            Ok(built) => built,
            Err(reason) => {
                return CedarDecision::Error {
                    reason,
                    policies: Vec::new(),
                }
            }
        };

        let response = Authorizer::new().is_authorized(&request, &self.policies, &entities);
        let diagnostics = response.diagnostics();

        // Cedar skips a policy that fails to evaluate. For a `forbid`, that
        // would let the call through, so any error denies it.
        let errors: Vec<_> = diagnostics.errors().collect();
        if !errors.is_empty() {
            let mut policies: Vec<String> = errors
                .iter()
                .map(|e| match e {
                    AuthorizationError::PolicyEvaluationError(e) => e.policy_id().to_string(),
                })
                .collect();
            policies.sort();
            policies.dedup();
            return CedarDecision::Error {
                reason: errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
                policies,
            };
        }

        let mut policies: Vec<String> = diagnostics.reason().map(ToString::to_string).collect();
        policies.sort();
        match (response.decision(), policies.is_empty()) {
            (Decision::Allow, _) => CedarDecision::Allow { policies },
            (Decision::Deny, false) => CedarDecision::Forbid { policies },
            (Decision::Deny, true) => CedarDecision::NotPermitted,
        }
    }

    /// The Cedar request and entities for a call, checked against the schema.
    fn build(&self, call: &CedarRequest<'_>) -> Result<(Request, Entities), String> {
        if self.tool_actions.contains(call.tool) {
            self.build_as(call, call.tool, call.arguments.clone())
        } else {
            self.build_as(call, CALL_ACTION, json!({}))
        }
    }

    fn build_as(
        &self,
        call: &CedarRequest<'_>,
        action_name: &str,
        arguments: Value,
    ) -> Result<(Request, Entities), String> {
        let action = uid("Action", action_name)?;
        let context = self.context(&action, call, arguments, call.labels)?;
        let entities = self.entities(call, call.labels.map(|_| call.external))?;
        let principal = uid("Agent", call.agent_id)?;
        let resource = uid("Tool", call.tool)?;
        let request = Request::new(principal, action, resource, context, Some(&self.schema))
            .map_err(|e| format!("the request doesn't match the schema: {}", error_chain(&e)))?;
        Ok((request, entities))
    }

    /// The context of a call to `action`, with `labels` if given.
    fn context(
        &self,
        action: &EntityUid,
        call: &CedarRequest<'_>,
        arguments: Value,
        labels: Option<&Label>,
    ) -> Result<Context, String> {
        let mut context = json!({ "session": call.session, "arguments": arguments });
        if let (Some(label), Some(map)) = (labels, context.as_object_mut()) {
            map.insert("labels".to_string(), label_json(label));
        }
        Context::from_json_value(context, Some((&self.schema, action))).map_err(|e| {
            format!(
                "the call doesn't match the schema for {action}: {}",
                error_chain(&e)
            )
        })
    }

    /// The principal and resource entities of a call, the tool with
    /// `external` if given.
    fn entities(
        &self,
        call: &CedarRequest<'_>,
        external: Option<bool>,
    ) -> Result<Entities, String> {
        // The record's attributes first, so they can't override what the
        // kernel itself knows.
        let mut agent_attrs: serde_json::Map<String, Value> = call
            .attributes
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        agent_attrs.insert("internal".to_string(), Value::Bool(call.internal));
        agent_attrs.insert(
            "name".to_string(),
            Value::String(call.agent_name.to_string()),
        );
        let mut tool_attrs = json!({ "restricted": call.restricted, "builtin": call.builtin });
        if let (Some(external), Some(map)) = (external, tool_attrs.as_object_mut()) {
            map.insert("external".to_string(), Value::Bool(external));
        }

        Entities::from_json_value(
            json!([
                {
                    "uid": { "type": format!("{NAMESPACE}::Agent"), "id": call.agent_id },
                    "attrs": agent_attrs,
                    "parents": [],
                },
                {
                    "uid": { "type": format!("{NAMESPACE}::Tool"), "id": call.tool },
                    "attrs": tool_attrs,
                    "parents": [],
                },
            ]),
            Some(&self.schema),
        )
        .map_err(|e| {
            format!(
                "the agent or tool doesn't match the schema: {}",
                error_chain(&e)
            )
        })
    }

    /// Checks that the schema accepts a generic call with what the kernel
    /// supplies, and returns whether that includes labels.
    ///
    /// A schema takes labels if every action that applies to requests
    /// declares `context.labels` and `Tool` declares `external`, all
    /// required. It takes none if it declares none of them. Anything in
    /// between is refused:
    ///
    /// - **Optional declarations.** An optional declaration would let a
    ///   `has`-guarded forbid skip, silently, every call that doesn't carry
    ///   labels.
    /// - **Partial declarations.** Labels on some actions and not others
    ///   can't be supplied whole.
    fn check_contract(&self, schema_text: &str) -> Result<bool, CedarPolicyError> {
        let declared = label_declarations(schema_text).map_err(CedarPolicyError::Contract)?;
        let mut optional: Vec<String> = declared
            .actions
            .iter()
            .filter(|(_, labels)| *labels == Some(false))
            .map(|(action, _)| format!("context.labels of {action}"))
            .collect();
        if declared.external == Some(false) {
            optional.push("Tool.external".to_string());
        }
        if !optional.is_empty() {
            return Err(CedarPolicyError::Contract(format!(
                "{} declared optional; declare context.labels on every action and \
                 Tool.external, all required, or none of them (docs/adr/0016)",
                optional.join(", ")
            )));
        }

        let with: Vec<&str> = declared
            .actions
            .iter()
            .filter(|(_, labels)| labels.is_some())
            .map(|(action, _)| action.as_str())
            .collect();
        let labelled = match (declared.external.is_some(), with.len()) {
            (true, n) if n == declared.actions.len() => true,
            (false, 0) => false,
            (external, _) => {
                let without: Vec<&str> = declared
                    .actions
                    .iter()
                    .filter(|(_, labels)| labels.is_none())
                    .map(|(action, _)| action.as_str())
                    .collect();
                return Err(CedarPolicyError::Contract(format!(
                    "labels are declared only in part (Tool.external {}; context.labels on \
                     [{}], not on [{}]); declare context.labels on every action and \
                     Tool.external, or none of them (docs/adr/0016)",
                    if external { "declared" } else { "not declared" },
                    with.join(", "),
                    without.join(", ")
                )));
            }
        };

        let attributes = HashMap::new();
        let arguments = json!({});
        let label = Label::trusted();
        let probe = CedarRequest {
            agent_id: "contract-check",
            agent_name: "contract-check",
            internal: false,
            attributes: &attributes,
            tool: "contract-check",
            restricted: false,
            builtin: false,
            session: "contract-check",
            arguments: &arguments,
            labels: labelled.then_some(&label),
            external: false,
        };
        self.build_as(&probe, CALL_ACTION, json!({}))
            .map(|_| labelled)
            .map_err(CedarPolicyError::Contract)
    }
}

/// Where a schema declares labels: for each of its actions that applies to
/// requests, whether its context declares `labels` (`Some(required)`), and
/// the same for `Tool.external`.
struct LabelDeclarations {
    actions: Vec<(String, Option<bool>)>,
    external: Option<bool>,
}

/// Reads the label declarations from the schema's JSON form.
///
/// # Errors
///
/// A description, if the schema doesn't convert or an action's context or
/// `Tool`'s shape can't be resolved to a record: the kernel can't tell
/// whether it declares labels.
fn label_declarations(schema_text: &str) -> Result<LabelDeclarations, String> {
    let (fragment, _) = cedar_policy::SchemaFragment::from_cedarschema_str(schema_text)
        .map_err(|e| error_chain(&e))?;
    let json = fragment.to_json_value().map_err(|e| error_chain(&e))?;
    let Some(namespace) = json.get(NAMESPACE) else {
        // Nothing the kernel supplies is declared; the contract probe says
        // what's missing.
        return Ok(LabelDeclarations {
            actions: Vec::new(),
            external: None,
        });
    };

    let mut actions = Vec::new();
    if let Some(declared) = namespace.get("actions").and_then(Value::as_object) {
        for (name, action) in declared {
            let applies = action.get("appliesTo");
            let principals = applies
                .and_then(|a| a.get("principalTypes"))
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            if principals == 0 {
                // An action group: no request is ever made for it.
                continue;
            }
            let labels = match applies.and_then(|a| a.get("context")) {
                None => None,
                Some(context) => {
                    let record = resolve_record(namespace, context).ok_or_else(|| {
                        format!("can't resolve the context type of action \"{name}\"")
                    })?;
                    attribute(record, "labels")
                }
            };
            actions.push((format!("Vak::Action::\"{name}\""), labels));
        }
    }

    let external = match namespace.get("entityTypes").and_then(|t| t.get("Tool")) {
        None => None,
        Some(tool) => match tool.get("shape") {
            None => None,
            Some(shape) => {
                let record = resolve_record(namespace, shape)
                    .ok_or_else(|| "can't resolve the shape of Tool".to_string())?;
                attribute(record, "external")
            }
        },
    };

    Ok(LabelDeclarations { actions, external })
}

/// `ty` as a record type, following references to the namespace's common
/// types. `None` if it doesn't resolve to a record.
fn resolve_record<'a>(namespace: &'a Value, mut ty: &'a Value) -> Option<&'a Value> {
    for _ in 0..16 {
        let kind = ty.get("type")?.as_str()?;
        if kind == "Record" {
            return Some(ty);
        }
        let name = if kind == "EntityOrCommon" {
            ty.get("name")?.as_str()?
        } else {
            kind
        };
        let name = name
            .strip_prefix(NAMESPACE)
            .and_then(|n| n.strip_prefix("::"))
            .unwrap_or(name);
        ty = namespace.get("commonTypes")?.get(name)?;
    }
    None
}

/// Whether `record` declares `name`: `Some(required)`, or `None`.
fn attribute(record: &Value, name: &str) -> Option<bool> {
    let declared = record.get("attributes")?.get(name)?;
    Some(
        declared
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    )
}

/// A label as Cedar policies read it: `{ integrity, public, readers,
/// sources }`. `integrity` is `"trusted"` or `"untrusted"`; `readers` is
/// empty when `public` is true.
fn label_json(label: &Label) -> Value {
    let readers: Vec<&str> = match &label.readers {
        Readers::Public => Vec::new(),
        Readers::Only(readers) => readers.iter().map(String::as_str).collect(),
    };
    let sources: Vec<String> = label.sources.iter().map(ToString::to_string).collect();
    json!({
        "integrity": label.integrity.as_str(),
        "public": label.readers.is_public(),
        "readers": readers,
        "sources": sources,
    })
}

/// `(file name, contents)` for each policy file in `paths`. A directory
/// contributes every `*.cedar` file directly in it.
fn read_sources(paths: &[PathBuf]) -> Result<Vec<(String, String)>, CedarPolicyError> {
    let mut sources = Vec::new();
    for path in paths {
        if path.is_dir() {
            // An entry that can't be read is an error, not a skip: it could
            // be the file holding the forbids.
            let mut files = std::fs::read_dir(path)
                .map_err(|e| io(path, &e))?
                .map(|entry| entry.map(|entry| entry.path()).map_err(|e| io(path, &e)))
                .collect::<Result<Vec<_>, _>>()?;
            files.retain(|p| p.is_file() && p.extension().is_some_and(|e| e == "cedar"));
            files.sort();
            for file in files {
                sources.push((origin(&file), read(&file)?));
            }
        } else {
            sources.push((origin(path), read(path)?));
        }
    }
    if sources.is_empty() {
        let where_ = paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CedarPolicyError::Empty(where_));
    }
    Ok(sources)
}

/// `Vak::<kind>::"<id>"`.
fn uid(kind: &str, id: &str) -> Result<EntityUid, String> {
    let type_name = format!("{NAMESPACE}::{kind}")
        .parse()
        .map_err(|e: cedar_policy::ParseErrors| e.to_string())?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        cedar_policy::EntityId::new(id),
    ))
}

fn read(path: &Path) -> Result<String, CedarPolicyError> {
    std::fs::read_to_string(path).map_err(|e| io(path, &e))
}

fn io(path: &Path, e: &std::io::Error) -> CedarPolicyError {
    CedarPolicyError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    }
}

/// The file name, for errors and default policy ids.
fn origin(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// An error and its sources, one after another. Cedar's top-level messages
/// are often generic ("error during entity deserialization"); the detail is
/// in the sources.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !message.contains(&cause_text) {
            message.push_str(": ");
            message.push_str(&cause_text);
        }
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_POLICIES: &str = include_str!("../../../policies/cedar/default.cedar");
    const PAYMENTS_SCHEMA: &str =
        include_str!("../../../policies/cedar/examples/payments.cedarschema");
    const PAYMENTS_POLICIES: &str = include_str!("../../../policies/cedar/examples/payments.cedar");
    const LABELS_SCHEMA: &str = include_str!("../../../policies/cedar/examples/labels.cedarschema");
    const LABELS_POLICIES: &str = include_str!("../../../policies/cedar/examples/labels.cedar");

    fn set(schema: &str, policies: &str) -> CedarPolicySet {
        CedarPolicySet::from_sources(schema, &[("test.cedar".to_string(), policies.to_string())])
            .unwrap()
    }

    fn load_error(schema: &str, policies: &str) -> CedarPolicyError {
        CedarPolicySet::from_sources(schema, &[("test.cedar".to_string(), policies.to_string())])
            .unwrap_err()
    }

    struct Call {
        tool: &'static str,
        restricted: bool,
        internal: bool,
        attributes: HashMap<String, Value>,
        arguments: Value,
        labels: Option<Label>,
        external: bool,
    }

    impl Call {
        fn to(tool: &'static str) -> Self {
            Self {
                tool,
                restricted: false,
                internal: false,
                attributes: HashMap::new(),
                arguments: json!({}),
                labels: None,
                external: false,
            }
        }

        fn decide(&self, policies: &CedarPolicySet) -> CedarDecision {
            policies.authorize(&CedarRequest {
                agent_id: "agent-1",
                agent_name: "tester",
                internal: self.internal,
                attributes: &self.attributes,
                tool: self.tool,
                restricted: self.restricted,
                builtin: false,
                session: "session-1",
                arguments: &self.arguments,
                labels: self.labels.as_ref(),
                external: self.external,
            })
        }
    }

    fn contract_error(schema: &str) -> String {
        match load_error(
            schema,
            r#"@id("allow") permit (principal, action, resource);"#,
        ) {
            CedarPolicyError::Contract(message) => message,
            other => panic!("expected a contract error, got {other:?}"),
        }
    }

    #[test]
    fn test_a_schema_takes_labels_whole_or_not_at_all() {
        assert!(set(LABELS_SCHEMA, LABELS_POLICIES).takes_labels());
        assert!(!set(VAK_SCHEMA, DEFAULT_POLICIES).takes_labels());

        // Optional declarations would let a `has`-guarded forbid skip calls
        // made while labels are off.
        let optional_context = LABELS_SCHEMA.replacen("labels: Labels }", "labels?: Labels }", 1);
        assert_ne!(optional_context, LABELS_SCHEMA);
        assert!(contract_error(&optional_context).contains("optional"));
        let optional_tool = LABELS_SCHEMA.replace("external: Bool", "external?: Bool");
        assert!(contract_error(&optional_tool).contains("optional"));

        // An action group applies to no request, so it needs no labels.
        let with_group =
            LABELS_SCHEMA.replacen("namespace Vak {", "namespace Vak {\n  action \"mail\";", 1);
        assert!(set(&with_group, LABELS_POLICIES).takes_labels());

        // A context given as a common type is read through it.
        let via_type = VAK_SCHEMA.replacen(
            "context: { session: String, arguments: {} },",
            "context: Ctx,",
            1,
        )
        .replacen(
            "namespace Vak {",
            "namespace Vak {\n  type Ctx = { session: String, arguments: {}, labels?: { integrity: String } };",
            1,
        );
        assert!(contract_error(&via_type).contains("optional"));

        // One without the other can't be supplied whole.
        let no_external = LABELS_SCHEMA.replace("external: Bool,", "");
        assert!(contract_error(&no_external).contains("only in part"));
        let no_context = LABELS_SCHEMA.replacen(", labels: Labels }", " }", 1);
        assert!(contract_error(&no_context).contains("only in part"));
    }

    fn labelled(integrity: &str, readers: Option<&[&str]>) -> Label {
        let mut label = Label::trusted();
        if integrity == "untrusted" {
            label = label.with_integrity(crate::kernel::ifc::Integrity::Untrusted);
        }
        if let Some(readers) = readers {
            label = label.with_readers(Readers::only(readers.iter().copied()));
        }
        label
    }

    #[test]
    fn test_policies_decide_on_labels() {
        let policies = set(LABELS_SCHEMA, LABELS_POLICIES);
        let mail = |to: &str, label: Label| Call {
            arguments: json!({"to": to, "body": "hi"}),
            labels: Some(label),
            external: true,
            ..Call::to("send_email")
        };

        assert!(mail("bob", labelled("trusted", None))
            .decide(&policies)
            .is_allowed());
        assert_eq!(
            mail("bob", labelled("untrusted", None)).decide(&policies),
            CedarDecision::Forbid {
                policies: vec!["no-external-call-on-untrusted-arguments".to_string()]
            }
        );
        assert!(mail("alice", labelled("trusted", Some(&["alice"])))
            .decide(&policies)
            .is_allowed());
        assert_eq!(
            mail("bob", labelled("trusted", Some(&["alice"]))).decide(&policies),
            CedarDecision::Forbid {
                policies: vec!["email-only-to-allowed-readers".to_string()]
            }
        );

        // A generic call reads labels too, and an internal tool may take
        // untrusted data.
        let fetch = |external, label| Call {
            labels: Some(label),
            external,
            ..Call::to("fetch")
        };
        assert!(!fetch(true, labelled("untrusted", None))
            .decide(&policies)
            .is_allowed());
        assert!(fetch(false, labelled("untrusted", None))
            .decide(&policies)
            .is_allowed());

        // Without a label the call doesn't match the schema.
        assert!(matches!(
            Call::to("fetch").decide(&policies),
            CedarDecision::Error { .. }
        ));
    }

    #[test]
    fn test_labels_declared_on_some_actions_only_are_refused() {
        let with_action = |labels: &str| {
            VAK_SCHEMA.replacen(
                "namespace Vak {",
                &format!(
                    r#"namespace Vak {{
  type Ctx = {{ session: String, arguments: {{ to: String }}, {labels} }};
  action "send_email" in ["call"] appliesTo {{
    principal: Agent,
    resource: Tool,
    context: Ctx,
  }};"#
                ),
                1,
            )
        };
        // A tool's own action declaring labels, optional, while the generic
        // action doesn't: calls to it would never carry them, and a
        // `has`-guarded forbid on them would never fire.
        let optional = contract_error(&with_action("labels?: { integrity: String }"));
        assert!(optional.contains("send_email"), "{optional}");
        assert!(optional.contains("optional"), "{optional}");

        // Required on one action only.
        let partial = contract_error(&with_action("labels: { integrity: String }"));
        assert!(partial.contains("only in part"), "{partial}");

        // Declaring nothing on the tool's action is fine.
        let plain = set(&with_action("note?: String"), DEFAULT_POLICIES);
        assert!(!plain.takes_labels());
    }

    #[test]
    fn test_default_policies_decide_tool_calls() {
        let policies = set(VAK_SCHEMA, DEFAULT_POLICIES);
        assert_eq!(
            Call::to("echo").decide(&policies),
            CedarDecision::Allow {
                policies: vec!["permit-safe-tools".to_string()]
            }
        );
        assert_eq!(
            Call::to("dd").decide(&policies),
            CedarDecision::Forbid {
                policies: vec!["forbid-dd".to_string()]
            }
        );
        let blocked = Call {
            restricted: true,
            ..Call::to("echo")
        };
        assert_eq!(blocked.decide(&policies), CedarDecision::NotPermitted);
    }

    #[test]
    fn test_a_policy_that_fails_to_evaluate_denies() {
        // Cedar on its own would skip this forbid and allow the call.
        let policies = set(
            PAYMENTS_SCHEMA,
            r#"
            @id("allow-all") permit (principal, action, resource);
            @id("overflowing-forbid")
            forbid (principal, action == Vak::Action::"transfer_funds", resource)
            when { context.arguments.amount * 9223372036854775807 > 0 };
            "#,
        );
        let call = Call {
            arguments: json!({"amount": 2, "currency": "USD", "to": "x"}),
            ..Call::to("transfer_funds")
        };
        match call.decide(&policies) {
            CedarDecision::Error { reason, policies } => {
                assert_eq!(policies, vec!["overflowing-forbid".to_string()]);
                assert!(reason.contains("overflow"), "{reason}");
            }
            other => panic!("expected an error, got {other:?}"),
        }
    }

    fn finance(arguments: Value) -> Call {
        Call {
            attributes: HashMap::from([("team".to_string(), json!("finance"))]),
            arguments,
            ..Call::to("transfer_funds")
        }
    }

    #[test]
    fn test_policies_read_typed_arguments() {
        let policies = set(PAYMENTS_SCHEMA, PAYMENTS_POLICIES);
        let small = finance(json!({"amount": 500, "currency": "USD", "to": "acct-9"}));
        assert!(small.decide(&policies).is_allowed());

        let large = finance(json!({"amount": 5000, "currency": "USD", "to": "acct-9"}));
        assert_eq!(large.decide(&policies), CedarDecision::NotPermitted);

        let yen = finance(json!({"amount": 5, "currency": "JPY", "to": "acct-9"}));
        assert_eq!(
            yen.decide(&policies),
            CedarDecision::Forbid {
                policies: vec!["transfers-in-usd-or-eur-only".to_string()]
            }
        );

        let mut outsider = finance(json!({"amount": 5, "currency": "USD", "to": "acct-9"}));
        outsider.attributes.clear();
        assert_eq!(outsider.decide(&policies), CedarDecision::NotPermitted);
    }

    #[test]
    fn test_arguments_that_do_not_match_the_schema_deny() {
        let policies = set(PAYMENTS_SCHEMA, PAYMENTS_POLICIES);
        for (case, arguments) in [
            (
                "extra field",
                json!({"amount": 5, "currency": "USD", "to": "x", "memo": "hi"}),
            ),
            ("missing field", json!({"amount": 5, "currency": "USD"})),
            (
                "float",
                json!({"amount": 5.5, "currency": "USD", "to": "x"}),
            ),
            (
                "string amount",
                json!({"amount": "5", "currency": "USD", "to": "x"}),
            ),
            ("not an object", json!("transfer everything")),
        ] {
            assert!(
                matches!(
                    finance(arguments).decide(&policies),
                    CedarDecision::Error { .. }
                ),
                "{case}"
            );
        }
    }

    #[test]
    fn test_an_undeclared_agent_attribute_denies() {
        let policies = set(VAK_SCHEMA, DEFAULT_POLICIES);
        let call = Call {
            attributes: HashMap::from([("clearance".to_string(), json!(3))]),
            ..Call::to("echo")
        };
        match call.decide(&policies) {
            CedarDecision::Error { reason, .. } => {
                assert!(reason.contains("clearance"), "{reason}");
            }
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn test_kernel_attributes_override_record_attributes() {
        let policies = set(
            VAK_SCHEMA,
            r#"@id("internal-only") permit (principal, action, resource) when { principal.internal };"#,
        );
        let call = Call {
            attributes: HashMap::from([("internal".to_string(), json!(true))]),
            ..Call::to("echo")
        };
        assert_eq!(call.decide(&policies), CedarDecision::NotPermitted);
    }

    #[test]
    fn test_tools_without_their_own_action_get_no_arguments() {
        let policies = set(PAYMENTS_SCHEMA, PAYMENTS_POLICIES);
        assert_eq!(
            policies.tool_actions().collect::<Vec<_>>(),
            vec!["transfer_funds"]
        );
        // Arguments to a tool with no action of its own never reach Cedar,
        // so they can't make the request invalid.
        let call = Call {
            arguments: json!({"anything": [1, 2, 3]}),
            ..Call::to("echo")
        };
        assert_eq!(call.decide(&policies), CedarDecision::NotPermitted);
    }

    #[test]
    fn test_loading_refuses_what_it_cannot_enforce() {
        assert!(matches!(
            load_error(
                VAK_SCHEMA,
                "permit (principal, action, resource) when { principal.clearance > 3 };"
            ),
            CedarPolicyError::Invalid(_)
        ));
        assert!(matches!(
            load_error(VAK_SCHEMA, "permit (principal, action, resource"),
            CedarPolicyError::Parse { .. }
        ));
        assert!(matches!(
            load_error(
                VAK_SCHEMA,
                "permit (principal == ?principal, action, resource);"
            ),
            CedarPolicyError::Template { .. }
        ));
        assert!(matches!(
            load_error(VAK_SCHEMA, "// nothing here\n"),
            CedarPolicyError::Empty(_)
        ));
        assert!(matches!(
            load_error(
                VAK_SCHEMA,
                r#"@id("a") permit (principal, action, resource);
                   @id("a") forbid (principal, action, resource);"#
            ),
            CedarPolicyError::DuplicateId(ref id) if id == "a"
        ));
        assert!(matches!(
            load_error("namespace Vak {", DEFAULT_POLICIES),
            CedarPolicyError::Schema(_)
        ));
        // A property file loaded as policies would grant what it bounds.
        assert!(matches!(
            load_error(
                VAK_SCHEMA,
                include_str!("../../../policies/cedar/properties/default.cedar")
            ),
            CedarPolicyError::PropertyAsPolicy { .. }
        ));
    }

    #[test]
    fn test_a_schema_must_accept_what_the_kernel_supplies() {
        // No `name` on agents.
        let schema = r#"
            namespace Vak {
              entity Agent { internal: Bool };
              entity Tool { restricted: Bool, builtin: Bool };
              action "call" appliesTo {
                principal: Agent, resource: Tool,
                context: { session: String, arguments: {} },
              };
            }"#;
        let error = load_error(schema, r#"permit (principal, action, resource);"#);
        assert!(matches!(error, CedarPolicyError::Contract(_)), "{error:?}");
    }

    #[test]
    fn test_policies_without_an_id_are_named_after_their_file() {
        let policies = set(VAK_SCHEMA, "permit (principal, action, resource);");
        assert_eq!(
            policies.policy_ids().collect::<Vec<_>>(),
            vec!["test.cedar/policy0"]
        );
    }

    #[test]
    fn test_load_reads_directories_of_cedar_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.cedar"), DEFAULT_POLICIES).unwrap();
        std::fs::write(
            dir.path().join("b.cedar"),
            r#"@id("extra") forbid (principal, action, resource == Vak::Tool::"shell");"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("notes.txt"), "not a policy").unwrap();

        let policies = CedarPolicySet::load(None, &[dir.path().to_path_buf()]).unwrap();
        assert_eq!(policies.policy_ids().count(), 5);
        assert!(!Call::to("shell").decide(&policies).is_allowed());

        let empty = tempfile::tempdir().unwrap();
        assert!(matches!(
            CedarPolicySet::load(None, &[empty.path().to_path_buf()]),
            Err(CedarPolicyError::Empty(_))
        ));
        assert!(matches!(
            CedarPolicySet::load(None, &[dir.path().join("missing.cedar")]),
            Err(CedarPolicyError::Io { .. })
        ));
    }
}
