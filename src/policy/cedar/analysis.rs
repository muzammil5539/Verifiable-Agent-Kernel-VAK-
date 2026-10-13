//! Proofs about whole Cedar policy sets, with SymCC (docs/adr/0009).
//!
//! Evaluation answers "is this request allowed?". This module answers
//! questions about *every* request the schema admits, using
//! [`cedar-policy-symcc`](cedar_policy_symcc) and the cvc5 SMT solver:
//!
//! - **Ceilings.** A ceiling is a Cedar policy set describing the most the
//!   policies may allow. It holds if every request the policies allow, the
//!   ceiling allows too. "No policy permits a restricted tool" is the
//!   ceiling `permit (principal, action, resource) when { !resource.restricted };`.
//! - **Floors.** A floor describes what the policies must keep allowing. It
//!   holds if every request the floor allows, the policies allow.
//! - **Never errors.** No policy can fail to evaluate on any request. The
//!   kernel denies a request on which a policy errors, so this is what makes
//!   the kernel's decisions equal Cedar's, and a floor hold for the kernel.
//! - **No widening.** A new policy set allows nothing the old one didn't:
//!   the check for a reload ([`check_reload`]).
//!
//! A property that fails comes with a counterexample: a request and entity
//! store on which it fails, re-run through the Cedar evaluator to confirm
//! it.
//!
//! Properties live in `.cedar` files. Each policy carries
//! `@property("<name>")` and `@kind("ceiling")` or `@kind("floor")`; the
//! policies sharing a name form that property's policy set. See
//! `policies/cedar/properties/`.
//!
//! The checks range over every request and entity store the schema admits,
//! not only the ones the kernel produces. A ceiling proven here therefore
//! holds for the kernel. A floor can fail on a request the kernel never
//! makes, such as a tool named `dd` that is also `builtin`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use cedar_policy::{Authorizer, Decision, Entities, Policy, PolicyId, PolicySet, Request};
use cedar_policy::{RequestEnv, ValidationMode, Validator};
use cedar_policy_symcc::solver::LocalSolver;
use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicy, CompiledPolicySet, Env};
use thiserror::Error;

use super::{error_chain, read_sources, CedarPolicyError, CedarPolicySet};

/// Why an analysis couldn't run. A property that doesn't hold is not an
/// error; it is a violation in the [`AnalysisReport`].
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AnalysisError {
    /// A property file couldn't be read, parsed or validated.
    #[error(transparent)]
    Load(#[from] CedarPolicyError),

    /// A property policy lacks `@property` or `@kind`, or a property mixes
    /// kinds.
    #[error("{origin}: {message}")]
    Property {
        /// The file the property came from.
        origin: String,
        /// What is wrong with it.
        message: String,
    },

    /// The solver couldn't be started or failed.
    #[error("SMT solver (cvc5): {0}")]
    Solver(String),

    /// SymCC couldn't compile or check a policy set.
    #[error("SymCC: {0}")]
    Symcc(String),

    /// The two policy sets being compared use different schemas.
    #[error("the two policy sets use different schemas, so they can't be compared")]
    SchemaChanged,
}

/// Whether a property bounds the policies from above or below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PropertyKind {
    /// The policies allow at most what the property allows.
    Ceiling,
    /// The policies allow at least what the property allows.
    Floor,
}

impl FromStr for PropertyKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ceiling" => Ok(Self::Ceiling),
            "floor" => Ok(Self::Floor),
            other => Err(format!(
                "@kind must be \"ceiling\" or \"floor\", not \"{other}\""
            )),
        }
    }
}

/// One named property: a policy set and how it bounds the policies.
#[derive(Debug, Clone)]
pub struct Property {
    name: String,
    kind: PropertyKind,
    policies: PolicySet,
}

impl Property {
    /// The property's name, from `@property`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Ceiling or floor.
    #[must_use]
    pub fn kind(&self) -> PropertyKind {
        self.kind
    }
}

/// Properties to prove about a policy set.
#[derive(Debug, Clone, Default)]
pub struct PolicyProperties {
    properties: Vec<Property>,
}

impl PolicyProperties {
    /// Loads the properties in `paths` (files, or directories of `*.cedar`
    /// files), validated against the schema of `policies`.
    ///
    /// # Errors
    ///
    /// [`AnalysisError::Load`] if a file can't be read, parsed or validated,
    /// and [`AnalysisError::Property`] if a policy lacks its annotations.
    pub fn load(policies: &CedarPolicySet, paths: &[PathBuf]) -> Result<Self, AnalysisError> {
        Self::from_sources(policies, &read_sources(paths)?)
    }

    /// Builds properties from `(origin, text)` pairs, validated against the
    /// schema of `policies`.
    ///
    /// # Errors
    ///
    /// As [`PolicyProperties::load`], less the I/O errors.
    pub fn from_sources(
        policies: &CedarPolicySet,
        sources: &[(String, String)],
    ) -> Result<Self, AnalysisError> {
        let mut grouped: BTreeMap<String, (PropertyKind, PolicySet)> = BTreeMap::new();
        for (origin, text) in sources {
            let parsed = PolicySet::from_str(text).map_err(|e| CedarPolicyError::Parse {
                origin: origin.clone(),
                message: error_chain(&e),
            })?;
            if parsed.templates().next().is_some() {
                return Err(CedarPolicyError::Template {
                    origin: origin.clone(),
                }
                .into());
            }
            let property_error = |message: String| AnalysisError::Property {
                origin: origin.clone(),
                message,
            };
            for policy in parsed.policies() {
                let name = policy.annotation("property").ok_or_else(|| {
                    property_error(format!("policy {} has no @property(\"…\")", policy.id()))
                })?;
                let kind: PropertyKind = policy
                    .annotation("kind")
                    .ok_or_else(|| property_error(format!("property {name} has no @kind(\"…\")")))?
                    .parse()
                    .map_err(|e| property_error(format!("property {name}: {e}")))?;

                let (existing, set) = grouped
                    .entry(name.to_string())
                    .or_insert_with(|| (kind, PolicySet::new()));
                if *existing != kind {
                    return Err(property_error(format!(
                        "property {name} is both a ceiling and a floor"
                    )));
                }
                let id = PolicyId::new(format!("{name}#{}", set.policies().count()));
                set.add(policy.new_id(id))
                    .map_err(|e| property_error(format!("property {name}: {}", error_chain(&e))))?;
            }
        }

        let validator = Validator::new(policies.schema.clone());
        let mut properties = Vec::new();
        for (name, (kind, set)) in grouped {
            let validation = validator.validate(&set, ValidationMode::Strict);
            if !validation.validation_passed() {
                return Err(CedarPolicyError::Invalid(
                    validation
                        .validation_errors()
                        .map(|e| format!("property {name}: {e}"))
                        .collect(),
                )
                .into());
            }
            properties.push(Property {
                name,
                kind,
                policies: set,
            });
        }
        Ok(Self { properties })
    }

    /// The properties, in name order.
    pub fn iter(&self) -> impl Iterator<Item = &Property> {
        self.properties.iter()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.properties.is_empty()
    }
}

/// One thing that was checked.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Check {
    /// A ceiling property.
    Ceiling(String),
    /// A floor property.
    Floor(String),
    /// That a policy never fails to evaluate.
    NeverErrors(String),
    /// That a new policy set allows nothing the old one didn't.
    NoWidening,
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ceiling(name) => write!(f, "ceiling {name}"),
            Self::Floor(name) => write!(f, "floor {name}"),
            Self::NeverErrors(policy) => write!(f, "policy {policy} never errors"),
            Self::NoWidening => write!(f, "the new policies allow nothing the old ones didn't"),
        }
    }
}

/// A request on which a check fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The request environment: principal type, action, resource type.
    pub environment: String,
    /// The request and entity store, as SymCC found them.
    pub counterexample: String,
    /// Whether evaluating the counterexample with the Cedar evaluator
    /// reproduces the failure. `false` would mean the analysis and the
    /// evaluator disagree, which is itself worth reporting.
    pub confirmed: bool,
}

/// The outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    /// What was checked.
    pub check: Check,
    /// Where it fails; empty if it holds.
    pub violations: Vec<Violation>,
}

impl CheckOutcome {
    /// Whether the check holds in every request environment.
    #[must_use]
    pub fn holds(&self) -> bool {
        self.violations.is_empty()
    }
}

/// The outcomes of an analysis.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalysisReport {
    /// One outcome per check, in a stable order.
    pub outcomes: Vec<CheckOutcome>,
}

impl AnalysisReport {
    /// Whether every check holds.
    #[must_use]
    pub fn holds(&self) -> bool {
        self.outcomes.iter().all(CheckOutcome::holds)
    }

    /// The checks that don't hold.
    pub fn failures(&self) -> impl Iterator<Item = &CheckOutcome> {
        self.outcomes.iter().filter(|o| !o.holds())
    }

    /// The outcome of `check`, if it ran.
    #[must_use]
    pub fn outcome(&self, check: &Check) -> Option<&CheckOutcome> {
        self.outcomes.iter().find(|o| &o.check == check)
    }
}

impl fmt::Display for AnalysisReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for outcome in &self.outcomes {
            if outcome.holds() {
                writeln!(f, "holds: {}", outcome.check)?;
                continue;
            }
            writeln!(f, "FAILS: {}", outcome.check)?;
            for violation in &outcome.violations {
                writeln!(f, "  for {}:", violation.environment)?;
                if !violation.confirmed {
                    writeln!(
                        f,
                        "  (the Cedar evaluator does not reproduce this counterexample)"
                    )?;
                }
                for line in violation.counterexample.lines() {
                    writeln!(f, "    {line}")?;
                }
            }
        }
        Ok(())
    }
}

/// Runs SymCC checks with a cvc5 process.
pub struct Analyzer {
    compiler: CedarSymCompiler<LocalSolver>,
}

impl fmt::Debug for Analyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Analyzer").finish_non_exhaustive()
    }
}

impl Analyzer {
    /// Starts cvc5: the executable named by the `CVC5` environment variable,
    /// or `cvc5` on `PATH`. SymCC is verified against cvc5 1.3.1.
    ///
    /// # Errors
    ///
    /// [`AnalysisError::Solver`] if cvc5 can't be started.
    pub fn new() -> Result<Self, AnalysisError> {
        let solver = LocalSolver::cvc5().map_err(|e| AnalysisError::Solver(error_chain(&e)))?;
        let compiler =
            CedarSymCompiler::new(solver).map_err(|e| AnalysisError::Solver(error_chain(&e)))?;
        Ok(Self { compiler })
    }

    /// Checks every property, and that no policy ever errors, in every
    /// request environment of the schema.
    ///
    /// # Errors
    ///
    /// [`AnalysisError::Symcc`] or [`AnalysisError::Solver`] if a check
    /// can't be run. A property that doesn't hold is reported, not an error.
    pub async fn check(
        &mut self,
        policies: &CedarPolicySet,
        properties: &PolicyProperties,
    ) -> Result<AnalysisReport, AnalysisError> {
        let mut outcomes: BTreeMap<Check, Vec<Violation>> = BTreeMap::new();
        for property in properties.iter() {
            let check = match property.kind {
                PropertyKind::Ceiling => Check::Ceiling(property.name.clone()),
                PropertyKind::Floor => Check::Floor(property.name.clone()),
            };
            outcomes.entry(check).or_default();
        }
        for policy in policies.policies.policies() {
            outcomes
                .entry(Check::NeverErrors(policy.id().to_string()))
                .or_default();
        }

        let schema = &policies.schema;
        for env in schema.request_envs() {
            let environment = describe(&env);
            let compiled = compile_set(&policies.policies, &env, policies)?;

            for property in properties.iter() {
                let bound = compile_set(&property.policies, &env, policies)?;
                // Everything `inner` allows, `outer` must allow. A ceiling:
                // the policies inside the property. A floor: the property
                // inside the policies.
                let (check, inner, outer, inner_set, outer_set) = match property.kind {
                    PropertyKind::Ceiling => (
                        Check::Ceiling(property.name.clone()),
                        &compiled,
                        &bound,
                        &policies.policies,
                        &property.policies,
                    ),
                    PropertyKind::Floor => (
                        Check::Floor(property.name.clone()),
                        &bound,
                        &compiled,
                        &property.policies,
                        &policies.policies,
                    ),
                };
                if let Some(cex) = self
                    .compiler
                    .check_implies_with_counterexample_opt(inner, outer)
                    .await
                    .map_err(|e| AnalysisError::Symcc(error_chain(&e)))?
                {
                    let confirmed = allows(inner_set, &cex.request, &cex.entities)
                        && !allows(outer_set, &cex.request, &cex.entities);
                    outcomes.entry(check).or_default().push(violation(
                        &environment,
                        &cex,
                        confirmed,
                    ));
                }
            }

            for policy in policies.policies.policies() {
                let compiled = CompiledPolicy::compile(policy, &env, schema)
                    .map_err(|e| AnalysisError::Symcc(error_chain(&e)))?;
                if let Some(cex) = self
                    .compiler
                    .check_never_errors_with_counterexample_opt(&compiled)
                    .await
                    .map_err(|e| AnalysisError::Symcc(error_chain(&e)))?
                {
                    let confirmed = errors(policy, &cex.request, &cex.entities);
                    outcomes
                        .entry(Check::NeverErrors(policy.id().to_string()))
                        .or_default()
                        .push(violation(&environment, &cex, confirmed));
                }
            }
        }

        Ok(AnalysisReport {
            outcomes: outcomes
                .into_iter()
                .map(|(check, violations)| CheckOutcome { check, violations })
                .collect(),
        })
    }

    /// Checks that `new` allows nothing `old` doesn't.
    ///
    /// # Errors
    ///
    /// [`AnalysisError::SchemaChanged`] if the sets use different schemas,
    /// and as [`Analyzer::check`].
    pub async fn check_no_widening(
        &mut self,
        old: &CedarPolicySet,
        new: &CedarPolicySet,
    ) -> Result<CheckOutcome, AnalysisError> {
        if old.schema_text != new.schema_text {
            return Err(AnalysisError::SchemaChanged);
        }
        let mut violations = Vec::new();
        for env in new.schema.request_envs() {
            let new_set = compile_set(&new.policies, &env, new)?;
            let old_set = compile_set(&old.policies, &env, old)?;
            if let Some(cex) = self
                .compiler
                .check_implies_with_counterexample_opt(&new_set, &old_set)
                .await
                .map_err(|e| AnalysisError::Symcc(error_chain(&e)))?
            {
                let confirmed = allows(&new.policies, &cex.request, &cex.entities)
                    && !allows(&old.policies, &cex.request, &cex.entities);
                violations.push(violation(&describe(&env), &cex, confirmed));
            }
        }
        Ok(CheckOutcome {
            check: Check::NoWidening,
            violations,
        })
    }
}

/// Whether a reload may widen access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Widening {
    /// Refuse a new policy set that allows anything the current one doesn't.
    Refuse,
    /// Accept one, as long as the properties still hold. For a reviewed
    /// change that is meant to grant access.
    Allow,
}

/// Why a reload was refused.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ReloadRefused {
    /// The analysis couldn't run, so nothing about the new set is known.
    #[error("the new policies couldn't be analysed: {0}")]
    Analysis(#[from] AnalysisError),

    /// A check failed on the new set.
    #[error("the new policies fail analysis:\n{0}")]
    Violations(AnalysisReport),
}

/// The checks a reload must pass: `new` has the same schema as `current`,
/// every property holds of `new`, no policy in `new` ever errors, and,
/// unless `widening` allows it, `new` allows nothing `current` doesn't.
///
/// The schema must not change: the properties were validated against it, and
/// a new schema changes what requests look like. That takes a restart.
///
/// # Errors
///
/// [`ReloadRefused`] if any check fails or can't run. A reload that can't be
/// proven safe is refused, not taken on trust.
pub async fn check_reload(
    analyzer: &mut Analyzer,
    current: &CedarPolicySet,
    new: &CedarPolicySet,
    properties: &PolicyProperties,
    widening: Widening,
) -> Result<AnalysisReport, ReloadRefused> {
    if current.schema_text != new.schema_text {
        return Err(AnalysisError::SchemaChanged.into());
    }
    let mut report = analyzer.check(new, properties).await?;
    if widening == Widening::Refuse {
        report
            .outcomes
            .push(analyzer.check_no_widening(current, new).await?);
    }
    if report.holds() {
        Ok(report)
    } else {
        Err(ReloadRefused::Violations(report))
    }
}

fn compile_set(
    policies: &PolicySet,
    env: &RequestEnv,
    set: &CedarPolicySet,
) -> Result<CompiledPolicySet, AnalysisError> {
    CompiledPolicySet::compile(policies, env, &set.schema)
        .map_err(|e| AnalysisError::Symcc(error_chain(&e)))
}

fn describe(env: &RequestEnv) -> String {
    format!(
        "principal {}, action {}, resource {}",
        env.principal(),
        env.action(),
        env.resource()
    )
}

fn violation(environment: &str, cex: &Env, confirmed: bool) -> Violation {
    Violation {
        environment: environment.to_string(),
        counterexample: cex.to_string(),
        confirmed,
    }
}

fn allows(policies: &PolicySet, request: &Request, entities: &Entities) -> bool {
    Authorizer::new()
        .is_authorized(request, policies, entities)
        .decision()
        == Decision::Allow
}

fn errors(policy: &Policy, request: &Request, entities: &Entities) -> bool {
    let mut alone = PolicySet::new();
    if alone.add(policy.clone()).is_err() {
        return false;
    }
    Authorizer::new()
        .is_authorized(request, &alone, entities)
        .diagnostics()
        .errors()
        .next()
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::cedar::VAK_SCHEMA;

    const DEFAULT_POLICIES: &str = include_str!("../../../policies/cedar/default.cedar");
    const DEFAULT_PROPERTIES: &str =
        include_str!("../../../policies/cedar/properties/default.cedar");

    fn policies() -> CedarPolicySet {
        CedarPolicySet::from_sources(
            VAK_SCHEMA,
            &[("default.cedar".to_string(), DEFAULT_POLICIES.to_string())],
        )
        .unwrap()
    }

    fn properties(text: &str) -> Result<PolicyProperties, AnalysisError> {
        PolicyProperties::from_sources(&policies(), &[("p.cedar".to_string(), text.to_string())])
    }

    #[test]
    fn test_shipped_properties_load() {
        let loaded = properties(DEFAULT_PROPERTIES).unwrap();
        let kinds: Vec<_> = loaded.iter().map(|p| (p.name(), p.kind())).collect();
        assert_eq!(
            kinds,
            vec![
                ("dangerous-tools-are-never-called", PropertyKind::Ceiling),
                ("restricted-tools-are-never-called", PropertyKind::Ceiling),
                ("unrestricted-builtins-stay-callable", PropertyKind::Floor),
            ]
        );
    }

    #[test]
    fn test_policies_sharing_a_name_form_one_property() {
        let loaded = properties(
            r#"
            @property("p") @kind("ceiling") permit (principal, action, resource) when { resource.builtin };
            @property("p") @kind("ceiling") permit (principal, action, resource) when { principal.internal };
            "#,
        )
        .unwrap();
        let only: Vec<_> = loaded.iter().collect();
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].policies.policies().count(), 2);
    }

    #[test]
    fn test_malformed_properties_are_refused() {
        for (case, text) in [
            (
                "no @property",
                r#"@kind("ceiling") permit (principal, action, resource);"#,
            ),
            (
                "no @kind",
                r#"@property("p") permit (principal, action, resource);"#,
            ),
            (
                "unknown kind",
                r#"@property("p") @kind("roof") permit (principal, action, resource);"#,
            ),
            (
                "mixed kinds",
                r#"@property("p") @kind("ceiling") permit (principal, action, resource);
                   @property("p") @kind("floor") permit (principal, action, resource);"#,
            ),
        ] {
            assert!(
                matches!(properties(text), Err(AnalysisError::Property { .. })),
                "{case}"
            );
        }
        assert!(matches!(
            properties(
                r#"@property("p") @kind("ceiling") permit (principal, action, resource) when { principal.clearance > 1 };"#
            ),
            Err(AnalysisError::Load(CedarPolicyError::Invalid(_)))
        ));
    }

    #[test]
    fn test_a_failing_report_says_where_and_why() {
        let report = AnalysisReport {
            outcomes: vec![
                CheckOutcome {
                    check: Check::Ceiling("c".to_string()),
                    violations: vec![Violation {
                        environment: "principal Vak::Agent".to_string(),
                        counterexample: "principal: Vak::Agent::\"\"".to_string(),
                        confirmed: true,
                    }],
                },
                CheckOutcome {
                    check: Check::NoWidening,
                    violations: Vec::new(),
                },
            ],
        };
        assert!(!report.holds());
        assert_eq!(report.failures().count(), 1);
        let text = report.to_string();
        assert!(text.contains("FAILS: ceiling c"), "{text}");
        assert!(text.contains("holds: the new policies"), "{text}");
        assert!(text.contains("principal: Vak::Agent"), "{text}");
    }
}
