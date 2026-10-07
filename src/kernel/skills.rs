//! WASM skills on the kernel's request path (feature `wasm`).
//!
//! The kernel's Execute stage resolves a tool name to a built-in, then a
//! host handler, then a skill from here. Everything that needs Wasmtime
//! lives in this module, so a kernel built with `default-features = false`
//! has no sandbox and answers [`KernelError::ToolNotFound`] for any name that
//! isn't a built-in or a registered handler (docs/adr/0006).
//!
//! - The [`SkillRegistry`] holds the skills whose signatures verified at
//!   load, each pinned to its module's digest (docs/adr/0005).
//! - The [`SandboxRuntime`] is built on the first skill call unless one was
//!   injected, and runs every call on `spawn_blocking` (docs/adr/0004).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::{OnceCell, RwLock};
use tracing::{info, warn};

use super::config::KernelConfig;
use super::types::{KernelError, ToolRequest};
use super::Dispatched;
use crate::sandbox::{
    SandboxConfig, SandboxError, SandboxRuntime, SandboxRuntimeConfig, SignatureConfig,
    SkillManifest, SkillRegistry, SkillSignatureVerifier,
};

/// The kernel's skills: which exist, the runtime they run on, and the limits
/// they run with.
pub(super) struct Skills {
    registry: Arc<RwLock<SkillRegistry>>,
    /// Built on the first skill call unless injected, so kernels that never
    /// run a skill don't pay for an engine or a ticker thread.
    runtime: OnceCell<Arc<SandboxRuntime>>,
    limits: SandboxConfig,
}

impl Skills {
    /// Skills as `config` describes them, unless a registry or runtime is
    /// supplied.
    ///
    /// The default registry loads manifests from `security.skills_path` (or
    /// `VAK_SKILLS_PATH`, `.github/skills`, `skills`) and accepts only skills
    /// signed by `security.trusted_skill_keys`, unless
    /// `security.allow_unsigned_skills` is set.
    pub(super) fn new(
        config: &KernelConfig,
        registry: Option<SkillRegistry>,
        runtime: Option<Arc<SandboxRuntime>>,
    ) -> Result<Self, KernelError> {
        let registry = match registry {
            Some(registry) => registry,
            None => Self::registry_from_config(config)?,
        };
        Ok(Self {
            registry: Arc::new(RwLock::new(registry)),
            runtime: OnceCell::new_with(runtime),
            limits: SandboxConfig {
                memory_limit: (config.resources.max_memory_mb as usize) * 1024 * 1024,
                fuel_limit: 10_000_000,
                timeout: config.max_execution_time,
            },
        })
    }

    fn registry_from_config(config: &KernelConfig) -> Result<SkillRegistry, KernelError> {
        // The path used to be hardcoded to "skills", which does not exist in
        // this repo (the skill crates live under .github/skills), so the
        // registry silently loaded nothing (Issue #6).
        let skills_dir = config
            .security
            .skills_path
            .clone()
            .unwrap_or_else(resolve_skills_dir);
        // Signed skills only, from the configured publishers, unless unsigned
        // skills are explicitly allowed. A trusted key that doesn't parse is a
        // configuration error, not a key to skip.
        let verifier = SkillSignatureVerifier::try_new(SignatureConfig {
            require_signatures: true,
            trusted_keys: config.security.trusted_skill_keys.clone(),
            allow_unsigned_in_dev: config.security.allow_unsigned_skills,
        })
        .map_err(|e| KernelError::InvalidConfiguration {
            message: format!("security.trusted_skill_keys: {e}"),
        })?;
        let mut registry = SkillRegistry::with_signature_verification(skills_dir.clone(), verifier);
        if skills_dir.exists() {
            match registry.load_all_skills() {
                Ok(ids) => info!(count = ids.len(), "Loaded skills from registry"),
                Err(e) => warn!(error = %e, "Failed to load skills from registry"),
            }
        }
        Ok(registry)
    }

    /// The runtime, if a skill has run or one was injected.
    pub(super) fn runtime(&self) -> Option<&Arc<SandboxRuntime>> {
        self.runtime.get()
    }

    /// Loads the skill `manifest` describes into the registry, verified as
    /// skills loaded at startup are, and returns its name.
    pub(super) async fn load(&self, manifest: &Path) -> Result<String, KernelError> {
        let mut registry = self.registry.write().await;
        let id = registry
            .load_skill(manifest)
            .map_err(|e| KernelError::SkillRejected {
                manifest: manifest.display().to_string(),
                reason: e.to_string(),
            })?;
        let name = registry
            .get_skill(&id)
            .map(|skill| skill.name.clone())
            .unwrap_or_default();
        info!(skill = %name, manifest = %manifest.display(), "Loaded skill");
        Ok(name)
    }

    /// The manifest of the loaded skill called `name`.
    pub(super) async fn manifest(&self, name: &str) -> Option<SkillManifest> {
        self.registry.read().await.get_skill_by_name(name).cloned()
    }

    /// Names of the loaded skills.
    pub(super) async fn names(&self) -> Vec<String> {
        self.registry
            .read()
            .await
            .list_skills()
            .into_iter()
            .map(|skill| skill.name.clone())
            .collect()
    }

    /// Executes a WASM skill in the sandbox (Issue #6)
    ///
    /// 1. Look the skill up in the registry by name, or fail with
    ///    [`KernelError::ToolNotFound`].
    /// 2. On a blocking-pool thread: prepare the module the skill was
    ///    verified with (cached by digest; a changed file is refused), then
    ///    run it with the kernel's fuel, memory and wall-clock limits.
    ///
    /// The skill never runs on a Tokio worker, so a slow or spinning skill
    /// can't stall other requests. A panic on the blocking thread fails this
    /// call only.
    pub(super) async fn execute(&self, request: &ToolRequest) -> Dispatched {
        let failed = |reason: String| KernelError::ToolExecutionFailed {
            tool_name: request.tool_name.clone(),
            reason,
        };

        // Copy what's needed and release the registry lock before running.
        // The digest is the module the skill was verified with at load; only
        // those bytes may run under its name.
        let found = {
            let registry = self.registry.read().await;
            registry
                .get_skill_by_name(&request.tool_name)
                .cloned()
                .zip(registry.module_digest(&request.tool_name))
        };
        let Some((manifest, pinned)) = found else {
            // Fail closed. This used to return a success response from a
            // "default handler" that executed nothing, so an agent could be
            // told an action happened when it hadn't.
            warn!(tool = %request.tool_name, "Tool not found");
            return Dispatched {
                result: Err(KernelError::ToolNotFound {
                    tool_name: request.tool_name.clone(),
                }),
                module_sha256: None,
            };
        };
        let module_sha256 = Some(hex::encode(pinned));
        info!(
            tool = %request.tool_name,
            version = %manifest.version,
            module_sha256 = ?module_sha256,
            "Executing WASM skill"
        );

        let runtime = match self
            .runtime
            .get_or_try_init(|| async {
                SandboxRuntime::new(SandboxRuntimeConfig::default()).map(Arc::new)
            })
            .await
        {
            Ok(runtime) => runtime.clone(),
            Err(e) => {
                return Dispatched {
                    result: Err(failed(format!("WASM runtime unavailable: {e}"))),
                    module_sha256,
                }
            }
        };
        let mut limits = self.limits.clone();
        limits.timeout = request.time_limit(limits.timeout);
        let input = request.parameters.clone();

        let joined = tokio::task::spawn_blocking(move || {
            let skill = runtime.prepare_file_pinned(&manifest.wasm_path, &pinned)?;
            runtime.execute_json(&skill, &limits, "execute", &input)
        })
        .await;

        let result = match joined {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(SandboxError::Timeout(limit))) => Err(KernelError::Timeout {
                timeout_ms: u64::try_from(limit.as_millis()).unwrap_or(u64::MAX),
            }),
            Ok(Err(e @ SandboxError::ModuleChanged { .. })) => {
                tracing::error!(tool = %request.tool_name, error = %e, "Refusing to run a module that changed since it was verified");
                Err(failed(e.to_string()))
            }
            Ok(Err(e)) => Err(failed(format!("WASM execution failed: {e}"))),
            Err(join_error) => {
                tracing::error!(tool = %request.tool_name, error = %join_error, "WASM skill execution panicked");
                Err(failed("skill execution panicked".to_string()))
            }
        };
        Dispatched {
            result,
            module_sha256,
        }
    }
}

/// Resolves the directory to load WASM skill manifests from when
/// `security.skills_path` isn't set.
///
/// `VAK_SKILLS_PATH` wins if set (containers mount skills elsewhere);
/// otherwise the first location that exists is used.
fn resolve_skills_dir() -> PathBuf {
    if let Ok(path) = std::env::var("VAK_SKILLS_PATH") {
        return PathBuf::from(path);
    }
    [".github/skills", "skills"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_dir())
        .unwrap_or_else(|| PathBuf::from("skills"))
}
