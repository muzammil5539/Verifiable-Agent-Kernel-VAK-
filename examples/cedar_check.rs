//! Prove properties of Cedar policies with SymCC, for CI (docs/adr/0009).
//!
//! ```text
//! cargo run --example cedar_check --features cedar-analysis -- \
//!     --policies <path>... [--schema <file>] [--properties <path>...] \
//!     [--baseline <path>...]
//! ```
//!
//! Loads the policies the way the kernel does (`policy.policy_paths`,
//! `policy.cedar_schema`) and checks, for every request the schema admits:
//!
//! - each property in `--properties` (ceilings and floors);
//! - that no policy can fail to evaluate;
//! - with `--baseline`, that the policies allow nothing the baseline policies
//!   don't (for example, the policies on the main branch).
//!
//! Exits 0 if every check holds, 1 if one fails (printing a counterexample
//! request for it), and 2 if the checks couldn't run. Needs cvc5 1.3.1:
//! the `CVC5` environment variable, or `cvc5` on `PATH`.

use std::path::PathBuf;
use std::process::ExitCode;

use vak::policy::cedar::analysis::{Analyzer, PolicyProperties};
use vak::policy::cedar::CedarPolicySet;

const USAGE: &str = "usage: cedar_check --policies <path>... [--schema <file>] \
                     [--properties <path>...] [--baseline <path>...]";

#[derive(Default)]
struct Args {
    schema: Option<PathBuf>,
    policies: Vec<PathBuf>,
    properties: Vec<PathBuf>,
    baseline: Vec<PathBuf>,
}

fn parse(args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut parsed = Args::default();
    let mut list: Option<&str> = None;
    for arg in args {
        match arg.as_str() {
            "--policies" | "--properties" | "--baseline" | "--schema" => {
                list = Some(match arg.as_str() {
                    "--policies" => "policies",
                    "--properties" => "properties",
                    "--baseline" => "baseline",
                    _ => "schema",
                });
            }
            flag if flag.starts_with("--") => return Err(format!("unknown flag {flag}\n{USAGE}")),
            value => {
                let path = PathBuf::from(value);
                match list {
                    Some("policies") => parsed.policies.push(path),
                    Some("properties") => parsed.properties.push(path),
                    Some("baseline") => parsed.baseline.push(path),
                    Some("schema") if parsed.schema.is_none() => parsed.schema = Some(path),
                    _ => return Err(format!("unexpected argument {value}\n{USAGE}")),
                }
            }
        }
    }
    if parsed.policies.is_empty() {
        return Err(USAGE.to_string());
    }
    Ok(parsed)
}

async fn run(args: Args) -> Result<bool, String> {
    let schema = args.schema.as_deref();
    let policies = CedarPolicySet::load(schema, &args.policies).map_err(|e| e.to_string())?;
    let properties = if args.properties.is_empty() {
        PolicyProperties::default()
    } else {
        PolicyProperties::load(&policies, &args.properties).map_err(|e| e.to_string())?
    };

    let mut analyzer = Analyzer::new().map_err(|e| e.to_string())?;
    let mut report = analyzer
        .check(&policies, &properties)
        .await
        .map_err(|e| e.to_string())?;
    if !args.baseline.is_empty() {
        let baseline = CedarPolicySet::load(schema, &args.baseline).map_err(|e| e.to_string())?;
        report.outcomes.push(
            analyzer
                .check_no_widening(&baseline, &policies)
                .await
                .map_err(|e| e.to_string())?,
        );
    }

    print!("{report}");
    Ok(report.holds())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    match run(args).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(message) => {
            eprintln!("cedar_check: {message}");
            ExitCode::from(2)
        }
    }
}
