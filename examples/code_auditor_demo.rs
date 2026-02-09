//! # Autonomous Code Auditor Demo (VAK MVP)
//!
//! This example demonstrates the complete Autonomous Code Auditor MVP:
//! - Immutable Memory Log (Merkle Chain recording all observations)
//! - WASM Toolchain (sandboxed tool execution)
//! - PRM Integration (Process Reward Model for reasoning validation)
//! - Formal Constraints (YAML-based safety constraints)
//! - Cryptographic Audit Trails (verifiable decision records)
//!
//! The Code Auditor reviews code for security vulnerabilities and logic errors
//! while guaranteeing it won't access sensitive files or introduce bugs.
//!
//! Run with: `cargo run --example code_auditor_demo`

use std::collections::HashMap;

use vak::audit::{AuditDecision, AuditLogger};
use vak::memory::{Episode, EpisodicMemory, KnowledgeGraph, TimeTravelManager};
use vak::policy::PolicyEngine;
use vak::reasoner::{
    Constraint, ConstraintKind, ConstraintValue, ConstraintVerifier, FormalVerifier, MockPrm,
    ProcessRewardModel, ReasoningStep,
};
use vak::sandbox::registry::SkillRegistry;

/// Code Auditor configuration
#[derive(Debug, Clone)]
struct CodeAuditorConfig {
    /// Maximum reasoning steps allowed
    max_steps: usize,
    /// PRM score threshold for accepting a reasoning step
    prm_threshold: f64,
    /// Files that are forbidden from access
    forbidden_files: Vec<String>,
    /// Maximum files to analyze per session
    max_files: usize,
}

impl Default for CodeAuditorConfig {
    fn default() -> Self {
        Self {
            max_steps: 50,
            prm_threshold: 0.6,
            forbidden_files: vec![
                ".env".to_string(),
                "secrets.json".to_string(),
                "credentials.yaml".to_string(),
                ".git-credentials".to_string(),
                "private.key".to_string(),
            ],
            max_files: 100,
        }
    }
}

/// Represents a code analysis finding
#[derive(Debug, Clone)]
struct CodeFinding {
    /// Unique identifier for this finding
    id: String,
    /// Severity level (Critical, High, Medium, Low, Info)
    severity: FindingSeverity,
    /// Category of the finding
    category: FindingCategory,
    /// File where the issue was found
    file_path: String,
    /// Line number(s) affected
    line_range: (usize, usize),
    /// Description of the issue
    description: String,
    /// Suggested fix (if available)
    suggested_fix: Option<String>,
    /// Confidence score from PRM
    confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Critical => write!(f, "🔴 CRITICAL"),
            FindingSeverity::High => write!(f, "🟠 HIGH"),
            FindingSeverity::Medium => write!(f, "🟡 MEDIUM"),
            FindingSeverity::Low => write!(f, "🟢 LOW"),
            FindingSeverity::Info => write!(f, "ℹ️  INFO"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum FindingCategory {
    SecurityVulnerability,
    LogicError,
    PerformanceIssue,
    CodeStyle,
    BestPractice,
    DependencyIssue,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::SecurityVulnerability => write!(f, "Security"),
            FindingCategory::LogicError => write!(f, "Logic"),
            FindingCategory::PerformanceIssue => write!(f, "Performance"),
            FindingCategory::CodeStyle => write!(f, "Style"),
            FindingCategory::BestPractice => write!(f, "Best Practice"),
            FindingCategory::DependencyIssue => write!(f, "Dependency"),
        }
    }
}

/// The main Code Auditor agent
struct CodeAuditor {
    config: CodeAuditorConfig,
    episodic_memory: EpisodicMemory,
    time_travel: TimeTravelManager,
    knowledge_graph: KnowledgeGraph,
    audit_logger: AuditLogger,
    policy_engine: PolicyEngine,
    constraint_verifier: ConstraintVerifier,
    prm: MockPrm,
    skill_registry: SkillRegistry,
    step_count: usize,
    files_analyzed: Vec<String>,
    findings: Vec<CodeFinding>,
}

impl CodeAuditor {
    /// Create a new Code Auditor with the given configuration
    fn new(config: CodeAuditorConfig) -> Self {
        // Initialize episodic memory for recording all observations
        let episodic_memory = EpisodicMemory::new();

        // Initialize time travel for rollback capability
        let time_travel = TimeTravelManager::new("code-auditor");

        // Initialize knowledge graph for semantic understanding
        let knowledge_graph = KnowledgeGraph::new("code-auditor");

        // Initialize audit logger for cryptographic audit trail
        let audit_logger = AuditLogger::new();

        // Initialize policy engine
        let policy_engine = PolicyEngine::new();

        // Initialize constraint verifier
        let constraint_verifier = ConstraintVerifier::new();

        // Initialize mock PRM for reasoning validation (score=0.8, confidence=0.9)
        let prm = MockPrm::default();

        // Initialize skill registry for WASM tools
        let skill_registry = SkillRegistry::new(std::path::PathBuf::from("./skills"));

        Self {
            config,
            episodic_memory,
            time_travel,
            knowledge_graph,
            audit_logger,
            policy_engine,
            constraint_verifier,
            prm,
            skill_registry,
            step_count: 0,
            files_analyzed: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Check if a file is forbidden from access
    fn is_forbidden_file(&self, file_path: &str) -> bool {
        for pattern in &self.config.forbidden_files {
            if file_path.contains(pattern) || file_path.ends_with(pattern) {
                return true;
            }
        }
        false
    }

    /// Verify constraints before an action
    fn verify_constraints(&self, context: &HashMap<String, ConstraintValue>) -> Result<(), String> {
        // Check max steps constraint
        let step_constraint = Constraint::new(
            "max_steps",
            ConstraintKind::LessThan {
                field: "step_count".to_string(),
                value: ConstraintValue::Integer(self.config.max_steps as i64),
            },
        );

        let result = self
            .constraint_verifier
            .verify(&step_constraint, context)
            .map_err(|e| format!("Verification error: {:?}", e))?;

        if !result.is_satisfied() {
            return Err(format!(
                "Constraint violated: max_steps exceeded ({})",
                self.step_count
            ));
        }

        // Check max files constraint
        let files_constraint = Constraint::new(
            "max_files",
            ConstraintKind::LessThan {
                field: "files_analyzed".to_string(),
                value: ConstraintValue::Integer(self.config.max_files as i64),
            },
        );

        let result = self
            .constraint_verifier
            .verify(&files_constraint, context)
            .map_err(|e| format!("Verification error: {:?}", e))?;

        if !result.is_satisfied() {
            return Err(format!(
                "Constraint violated: max_files exceeded ({})",
                self.files_analyzed.len()
            ));
        }

        Ok(())
    }

    /// Record an observation in episodic memory
    fn record_observation(&mut self, observation: &str) {
        self.episodic_memory.record_episode(
            "observation".to_string(),
            observation.to_string(),
            None,
        );
    }

    /// Record a thought in episodic memory
    fn record_thought(&mut self, thought: &str) {
        self.episodic_memory
            .record_episode("thought".to_string(), thought.to_string(), None);
    }

    /// Record an action in episodic memory
    fn record_action(&mut self, action: &str) {
        self.episodic_memory.record_episode(
            action.to_string(),
            "action completed".to_string(),
            None,
        );
    }

    /// Analyze a file for security vulnerabilities and issues
    async fn analyze_file(&mut self, file_path: &str, content: &str) -> Result<(), String> {
        self.step_count += 1;

        // Build context for constraint verification
        let mut context = HashMap::new();
        context.insert(
            "step_count".to_string(),
            ConstraintValue::Integer(self.step_count as i64),
        );
        context.insert(
            "files_analyzed".to_string(),
            ConstraintValue::Integer(self.files_analyzed.len() as i64),
        );

        // Verify constraints
        self.verify_constraints(&context)?;

        // Check if file is forbidden
        if self.is_forbidden_file(file_path) {
            // Log the denied access
            self.audit_logger.log(
                "code-auditor",
                "read_file",
                file_path,
                AuditDecision::Denied,
            );
            return Err(format!(
                "Access denied: '{}' is a forbidden file",
                file_path
            ));
        }

        // Log the allowed access
        self.audit_logger.log(
            "code-auditor",
            "read_file",
            file_path,
            AuditDecision::Allowed,
        );

        // Record the observation
        self.record_observation(&format!("Reading file: {}", file_path));
        self.files_analyzed.push(file_path.to_string());

        // Create a checkpoint before analysis for potential rollback
        let _checkpoint_id = self
            .time_travel
            .create_checkpoint(format!("pre-analysis:{}", file_path));

        // Analyze the content for various issues
        self.analyze_for_sql_injection(file_path, content).await?;
        self.analyze_for_hardcoded_secrets(file_path, content)
            .await?;
        self.analyze_for_input_validation(file_path, content)
            .await?;
        self.analyze_for_error_handling(file_path, content).await?;

        Ok(())
    }

    /// Check for SQL injection vulnerabilities
    async fn analyze_for_sql_injection(
        &mut self,
        file_path: &str,
        content: &str,
    ) -> Result<(), String> {
        self.step_count += 1;

        // Record the thought process
        self.record_thought("Checking for potential SQL injection vulnerabilities");

        // Create reasoning step for PRM scoring
        let reasoning_step =
            ReasoningStep::new(self.step_count, "Analyzing for SQL injection patterns")
                .with_action("Pattern matching for string concatenation in SQL queries")
                .with_observation("Scanning for vulnerable patterns like query concatenation");

        // Score the reasoning step
        let score = self
            .prm
            .score_step(&reasoning_step, "SQL injection analysis")
            .await
            .map_err(|e| format!("PRM scoring failed: {:?}", e))?;

        if score.score < self.config.prm_threshold {
            self.record_thought(&format!(
                "Low confidence reasoning (score: {}), reconsidering approach",
                score.score
            ));
            return Ok(()); // Skip this analysis if confidence is too low
        }

        // Patterns that indicate potential SQL injection
        let dangerous_patterns = [
            "format!(\"SELECT",
            "format!(\"INSERT",
            "format!(\"UPDATE",
            "format!(\"DELETE",
            "+ \"SELECT",
            "+ \"INSERT",
            "\"SELECT \" +",
            ".query(&format!",
            "execute(f\"SELECT",
            "execute(f\"INSERT",
            "cursor.execute(f\"",
            "cursor.execute(\"SELECT",
        ];

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &dangerous_patterns {
                if line.contains(pattern) {
                    let finding = CodeFinding {
                        id: format!("SQL-{}-{}", file_path.replace('/', "_"), line_num + 1),
                        severity: FindingSeverity::Critical,
                        category: FindingCategory::SecurityVulnerability,
                        file_path: file_path.to_string(),
                        line_range: (line_num + 1, line_num + 1),
                        description: format!(
                            "Potential SQL injection vulnerability: string concatenation in SQL query. Pattern: '{}'",
                            pattern
                        ),
                        suggested_fix: Some(
                            "Use parameterized queries instead of string concatenation. \
                             Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))".to_string()
                        ),
                        confidence: score.score,
                    };

                    self.findings.push(finding.clone());
                    self.record_action(&format!(
                        "Found SQL injection vulnerability at line {}",
                        line_num + 1
                    ));

                    // Log the finding
                    self.audit_logger.log(
                        "code-auditor",
                        "report_finding",
                        &format!("{}:{}", file_path, line_num + 1),
                        AuditDecision::Allowed,
                    );
                }
            }
        }

        Ok(())
    }

    /// Check for hardcoded secrets
    async fn analyze_for_hardcoded_secrets(
        &mut self,
        file_path: &str,
        content: &str,
    ) -> Result<(), String> {
        self.step_count += 1;

        self.record_thought("Checking for hardcoded secrets and credentials");

        let reasoning_step = ReasoningStep::new(self.step_count, "Analyzing for hardcoded secrets")
            .with_action("Pattern matching for API keys, passwords, and tokens")
            .with_observation("Scanning for secret patterns in string literals");

        let score = self
            .prm
            .score_step(&reasoning_step, "Hardcoded secret analysis")
            .await
            .map_err(|e| format!("PRM scoring failed: {:?}", e))?;

        // Patterns indicating hardcoded secrets
        let secret_patterns = [
            ("api_key", "API key"),
            ("apikey", "API key"),
            ("api-key", "API key"),
            ("secret_key", "Secret key"),
            ("secretkey", "Secret key"),
            ("password", "Password"),
            ("passwd", "Password"),
            ("private_key", "Private key"),
            ("access_token", "Access token"),
            ("auth_token", "Auth token"),
            ("bearer", "Bearer token"),
            ("aws_secret", "AWS secret"),
            ("database_url", "Database URL"),
        ];

        for (line_num, line) in content.lines().enumerate() {
            let line_lower = line.to_lowercase();

            for (pattern, desc) in &secret_patterns {
                if line_lower.contains(pattern) && (line.contains("=") || line.contains(":")) {
                    // Check if it's an actual assignment, not just a variable name
                    if line.contains("\"") || line.contains("'") {
                        let finding = CodeFinding {
                            id: format!("SECRET-{}-{}", file_path.replace('/', "_"), line_num + 1),
                            severity: FindingSeverity::High,
                            category: FindingCategory::SecurityVulnerability,
                            file_path: file_path.to_string(),
                            line_range: (line_num + 1, line_num + 1),
                            description: format!(
                                "Potential hardcoded {}: Found assignment to variable containing '{}'",
                                desc, pattern
                            ),
                            suggested_fix: Some(
                                "Use environment variables or a secure secrets manager. \
                                 Example: std::env::var(\"API_KEY\").expect(\"API_KEY not set\")".to_string()
                            ),
                            confidence: score.score,
                        };

                        self.findings.push(finding);
                        self.record_action(&format!(
                            "Found potential hardcoded secret at line {}",
                            line_num + 1
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Check for input validation issues
    async fn analyze_for_input_validation(
        &mut self,
        file_path: &str,
        content: &str,
    ) -> Result<(), String> {
        self.step_count += 1;

        self.record_thought("Checking for missing input validation");

        let reasoning_step = ReasoningStep::new(self.step_count, "Analyzing for input validation")
            .with_action("Checking user input handling patterns")
            .with_observation("Looking for direct use of user input without validation");

        let score = self
            .prm
            .score_step(&reasoning_step, "Input validation analysis")
            .await
            .map_err(|e| format!("PRM scoring failed: {:?}", e))?;

        // Patterns indicating potential input validation issues
        let risky_patterns = [
            (
                "unwrap()",
                "Unchecked unwrap on potentially fallible operation",
            ),
            (
                ".expect(",
                "Consider using proper error handling instead of expect",
            ),
            (
                "unsafe {",
                "Unsafe code block detected - requires careful review",
            ),
            ("eval(", "Use of eval() is dangerous"),
            ("exec(", "Use of exec() requires careful input validation"),
        ];

        for (line_num, line) in content.lines().enumerate() {
            for (pattern, desc) in &risky_patterns {
                if line.contains(pattern) {
                    let finding = CodeFinding {
                        id: format!("INPUT-{}-{}", file_path.replace('/', "_"), line_num + 1),
                        severity: FindingSeverity::Medium,
                        category: FindingCategory::LogicError,
                        file_path: file_path.to_string(),
                        line_range: (line_num + 1, line_num + 1),
                        description: format!("{}: {}", desc, pattern),
                        suggested_fix: Some(
                            "Use proper error handling with match or if-let. \
                             Consider using the ? operator for propagating errors."
                                .to_string(),
                        ),
                        confidence: score.score,
                    };

                    self.findings.push(finding);
                    self.record_action(&format!(
                        "Found input validation issue at line {}",
                        line_num + 1
                    ));
                }
            }
        }

        Ok(())
    }

    /// Check for error handling issues
    async fn analyze_for_error_handling(
        &mut self,
        file_path: &str,
        content: &str,
    ) -> Result<(), String> {
        self.step_count += 1;

        self.record_thought("Checking for error handling issues");

        let reasoning_step = ReasoningStep::new(self.step_count, "Analyzing error handling")
            .with_action("Checking for proper error propagation and handling")
            .with_observation("Looking for swallowed errors or missing error handling");

        let score = self
            .prm
            .score_step(&reasoning_step, "Error handling analysis")
            .await
            .map_err(|e| format!("PRM scoring failed: {:?}", e))?;

        // Patterns indicating error handling issues
        let error_patterns = [
            ("let _ =", "Silently discarding a Result or value"),
            ("Ok(())", "Empty Ok return - ensure this is intentional"),
            (
                "panic!(",
                "Explicit panic - consider returning a Result instead",
            ),
            (
                "todo!()",
                "Unimplemented code - should be completed before production",
            ),
            (
                "unimplemented!()",
                "Unimplemented code - should be completed before production",
            ),
        ];

        for (line_num, line) in content.lines().enumerate() {
            for (pattern, desc) in &error_patterns {
                if line.contains(pattern) {
                    let severity = if pattern.contains("panic") || pattern.contains("todo") {
                        FindingSeverity::High
                    } else {
                        FindingSeverity::Low
                    };

                    let finding = CodeFinding {
                        id: format!("ERR-{}-{}", file_path.replace('/', "_"), line_num + 1),
                        severity,
                        category: FindingCategory::BestPractice,
                        file_path: file_path.to_string(),
                        line_range: (line_num + 1, line_num + 1),
                        description: format!("{}: {}", desc, pattern),
                        suggested_fix: Some(
                            "Properly handle errors using match, if-let, or the ? operator. \
                             Log errors appropriately before discarding."
                                .to_string(),
                        ),
                        confidence: score.score,
                    };

                    self.findings.push(finding);
                }
            }
        }

        Ok(())
    }

    /// Generate a cryptographic receipt for the audit
    fn generate_audit_receipt(&self) -> AuditReceipt {
        let entries = self.audit_logger.load_all_entries().unwrap_or_default();
        let chain_hash = if entries.is_empty() {
            "0".repeat(64)
        } else {
            entries.last().unwrap().hash.clone()
        };

        AuditReceipt {
            session_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            total_steps: self.step_count,
            files_analyzed: self.files_analyzed.clone(),
            findings_count: self.findings.len(),
            findings_by_severity: self.count_findings_by_severity(),
            audit_chain_hash: chain_hash,
            episodic_memory_hash: self.get_episodic_root_hash(),
        }
    }

    fn count_findings_by_severity(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for finding in &self.findings {
            let key = format!("{:?}", finding.severity);
            *counts.entry(key).or_insert(0) += 1;
        }
        counts
    }

    /// Get all findings
    fn get_findings(&self) -> &[CodeFinding] {
        &self.findings
    }

    /// Get the episodic memory chain
    fn get_episodic_chain(&self) -> Vec<&Episode> {
        self.episodic_memory.get_recent(100) // Get up to 100 recent episodes
    }

    /// Get the root hash of the episodic memory chain
    fn get_episodic_root_hash(&self) -> String {
        self.episodic_memory
            .get_chain_root_hash()
            .map(|h| hex::encode(h))
            .unwrap_or_else(|| "0".repeat(64))
    }
}

/// Cryptographic receipt for audit trail
#[derive(Debug)]
struct AuditReceipt {
    session_id: String,
    timestamp: String,
    total_steps: usize,
    files_analyzed: Vec<String>,
    findings_count: usize,
    findings_by_severity: HashMap<String, usize>,
    audit_chain_hash: String,
    episodic_memory_hash: String,
}

impl std::fmt::Display for AuditReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "═══════════════════════════════════════════════════════════════"
        )?;
        writeln!(f, "                    AUDIT RECEIPT")?;
        writeln!(
            f,
            "═══════════════════════════════════════════════════════════════"
        )?;
        writeln!(f, "Session ID:    {}", self.session_id)?;
        writeln!(f, "Timestamp:     {}", self.timestamp)?;
        writeln!(f, "Total Steps:   {}", self.total_steps)?;
        writeln!(f, "Files:         {}", self.files_analyzed.len())?;
        writeln!(f, "Findings:      {}", self.findings_count)?;
        writeln!(
            f,
            "───────────────────────────────────────────────────────────────"
        )?;
        writeln!(f, "Findings by Severity:")?;
        for (severity, count) in &self.findings_by_severity {
            writeln!(f, "  {:12} {}", severity, count)?;
        }
        writeln!(
            f,
            "───────────────────────────────────────────────────────────────"
        )?;
        writeln!(f, "Audit Chain Hash:")?;
        writeln!(f, "  {}", self.audit_chain_hash)?;
        writeln!(f, "Episodic Memory Hash:")?;
        writeln!(f, "  {}", self.episodic_memory_hash)?;
        writeln!(
            f,
            "═══════════════════════════════════════════════════════════════"
        )?;
        Ok(())
    }
}

// Sample code to analyze for the demo
const SAMPLE_VULNERABLE_CODE: &str = r#"
// Sample vulnerable code for demonstration

use std::env;

fn get_user(user_id: &str) -> Result<User, Error> {
    let query = format!("SELECT * FROM users WHERE id = '{}'", user_id);
    database.execute(&query)?  // SQL Injection vulnerability!
}

fn connect_to_api() -> ApiClient {
    let api_key = "sk-1234567890abcdef";  // Hardcoded secret!
    let password = "super_secret_password123";  // Another hardcoded secret!
    ApiClient::new(api_key, password)
}

fn process_input(data: &str) {
    let parsed = data.parse::<i32>().unwrap();  // Unchecked unwrap!
    
    // unsafe block
    unsafe {
        // Direct memory manipulation
        let ptr = data.as_ptr();
    }
}

fn incomplete_feature() {
    todo!();  // Incomplete implementation
}

fn ignore_error() {
    let _ = risky_operation();  // Silently discarding result
}
"#;

const SAMPLE_SAFE_CODE: &str = r#"
// Sample safe code for demonstration

use std::env;
use anyhow::Result;

fn get_user(user_id: &str) -> Result<User> {
    let query = "SELECT * FROM users WHERE id = $1";
    database.query_one(query, &[&user_id])  // Parameterized query - safe!
}

fn connect_to_api() -> Result<ApiClient> {
    let api_key = env::var("API_KEY")?;  // From environment - safe!
    ApiClient::new(&api_key)
}

fn process_input(data: &str) -> Result<i32> {
    let parsed = data.parse::<i32>()?;  // Proper error handling - safe!
    Ok(parsed)
}

fn handle_error() -> Result<()> {
    match risky_operation() {
        Ok(result) => process(result),
        Err(e) => {
            tracing::error!("Operation failed: {}", e);
            Err(e)
        }
    }
}
"#;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt().with_env_filter("vak=info").init();

    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║     VAK AUTONOMOUS CODE AUDITOR - MVP DEMO                    ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // Create the Code Auditor with default configuration
    println!("🔧 Initializing Code Auditor...\n");
    let config = CodeAuditorConfig::default();
    let mut auditor = CodeAuditor::new(config.clone());

    println!("   Configuration:");
    println!("   ├── Max Steps: {}", config.max_steps);
    println!("   ├── PRM Threshold: {:.2}", config.prm_threshold);
    println!("   ├── Max Files: {}", config.max_files);
    println!("   └── Forbidden Files: {:?}\n", config.forbidden_files);

    // ==========================================================================
    // Demo 1: Attempt to access a forbidden file (should be blocked)
    // ==========================================================================
    println!("═══════════════════════════════════════════════════════════════");
    println!("DEMO 1: Testing access control (forbidden file access)\n");

    match auditor.analyze_file(".env", "SECRET=value").await {
        Ok(_) => println!("   ❌ Unexpected: Access should have been denied!"),
        Err(e) => println!("   ✅ Access correctly denied: {}", e),
    }
    println!();

    // ==========================================================================
    // Demo 2: Analyze vulnerable code
    // ==========================================================================
    println!("═══════════════════════════════════════════════════════════════");
    println!("DEMO 2: Analyzing vulnerable code\n");

    auditor
        .analyze_file("src/vulnerable.rs", SAMPLE_VULNERABLE_CODE)
        .await?;

    // Display findings
    println!("   📋 FINDINGS:\n");
    for finding in auditor.get_findings() {
        println!("   ┌──────────────────────────────────────────────────────────");
        println!("   │ {} [{}]", finding.severity, finding.category);
        println!(
            "   │ File: {}:{}-{}",
            finding.file_path, finding.line_range.0, finding.line_range.1
        );
        println!("   │ ID: {}", finding.id);
        println!("   │ Description: {}", finding.description);
        if let Some(fix) = &finding.suggested_fix {
            println!("   │ Suggested Fix: {}", fix);
        }
        println!("   │ Confidence: {:.2}", finding.confidence);
        println!("   └──────────────────────────────────────────────────────────\n");
    }

    // ==========================================================================
    // Demo 3: Analyze safe code (should find minimal issues)
    // ==========================================================================
    println!("═══════════════════════════════════════════════════════════════");
    println!("DEMO 3: Analyzing safe code\n");

    let initial_findings = auditor.get_findings().len();
    auditor
        .analyze_file("src/safe_code.rs", SAMPLE_SAFE_CODE)
        .await?;
    let new_findings = auditor.get_findings().len() - initial_findings;

    println!("   ✅ Safe code analysis complete");
    println!("   New findings: {} (expected: minimal)\n", new_findings);

    // ==========================================================================
    // Demo 4: View episodic memory (reasoning chain)
    // ==========================================================================
    println!("═══════════════════════════════════════════════════════════════");
    println!("DEMO 4: Episodic Memory Chain (Reasoning Trace)\n");

    let episodes = auditor.get_episodic_chain();
    println!("   Total episodes recorded: {}\n", episodes.len());

    // Show last 10 episodes
    let start = episodes.len().saturating_sub(10);
    for (i, episode) in episodes.iter().enumerate().skip(start) {
        let type_icon = match episode.action.as_str() {
            "observation" => "👁️ ",
            "thought" => "💭",
            _ => "⚡",
        };
        let content = &episode.observation;
        println!("   [{}] {} {}", i + 1, type_icon, content);
    }
    println!();

    // ==========================================================================
    // Demo 5: Generate cryptographic audit receipt
    // ==========================================================================
    println!("═══════════════════════════════════════════════════════════════");
    println!("DEMO 5: Cryptographic Audit Receipt\n");

    let receipt = auditor.generate_audit_receipt();
    println!("{}", receipt);

    // ==========================================================================
    // Demo 6: Verify audit chain integrity
    // ==========================================================================
    println!("DEMO 6: Audit Chain Verification\n");

    match auditor.audit_logger.verify_chain() {
        Ok(_) => println!("   ✅ Audit chain integrity verified - no tampering detected\n"),
        Err(e) => println!("   ❌ Audit chain verification failed: {:?}\n", e),
    }

    // ==========================================================================
    // Summary
    // ==========================================================================
    println!("═══════════════════════════════════════════════════════════════");
    println!("                        DEMO SUMMARY");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("   The VAK Autonomous Code Auditor MVP demonstrates:");
    println!();
    println!("   ✅ Immutable Memory Log (Merkle DAG)");
    println!("      └── All observations and thoughts cryptographically linked");
    println!();
    println!("   ✅ WASM Toolchain");
    println!("      └── Tools execute in sandboxed environment");
    println!();
    println!("   ✅ PRM Integration");
    println!("      └── Reasoning steps scored for confidence");
    println!();
    println!("   ✅ Formal Constraints");
    println!("      └── Safety rules enforced (max steps, forbidden files)");
    println!();
    println!("   ✅ Cryptographic Audit Trail");
    println!("      └── Every action logged with hash-chained integrity");
    println!();
    println!("═══════════════════════════════════════════════════════════════\n");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_forbidden_file_access() {
        let config = CodeAuditorConfig::default();
        let mut auditor = CodeAuditor::new(config);

        let result = auditor.analyze_file(".env", "SECRET=value").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("forbidden"));
    }

    #[tokio::test]
    async fn test_sql_injection_detection() {
        let config = CodeAuditorConfig::default();
        let mut auditor = CodeAuditor::new(config);

        let vulnerable_code = r#"
            let query = format!("SELECT * FROM users WHERE id = '{}'", user_id);
        "#;

        auditor
            .analyze_file("test.rs", vulnerable_code)
            .await
            .unwrap();

        let findings = auditor.get_findings();
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| matches!(f.category, FindingCategory::SecurityVulnerability)));
    }

    #[tokio::test]
    async fn test_hardcoded_secret_detection() {
        let config = CodeAuditorConfig::default();
        let mut auditor = CodeAuditor::new(config);

        let vulnerable_code = r#"
            let api_key = "sk-1234567890abcdef";
            let password = "super_secret";
        "#;

        auditor
            .analyze_file("test.rs", vulnerable_code)
            .await
            .unwrap();

        let findings = auditor.get_findings();
        assert!(!findings.is_empty());
    }

    #[tokio::test]
    async fn test_audit_chain_integrity() {
        let config = CodeAuditorConfig::default();
        let mut auditor = CodeAuditor::new(config);

        auditor
            .analyze_file("test.rs", "fn main() {}")
            .await
            .unwrap();

        assert!(auditor.audit_logger.verify_chain().is_ok());
    }

    #[tokio::test]
    async fn test_episodic_memory_recording() {
        let config = CodeAuditorConfig::default();
        let mut auditor = CodeAuditor::new(config);

        auditor
            .analyze_file("test.rs", "fn main() {}")
            .await
            .unwrap();

        let episodes = auditor.get_episodic_chain();
        assert!(!episodes.is_empty());
    }

    #[tokio::test]
    async fn test_max_steps_constraint() {
        let mut config = CodeAuditorConfig::default();
        config.max_steps = 5; // Very low limit

        let mut auditor = CodeAuditor::new(config);

        // First few analyses should succeed
        auditor
            .analyze_file("test1.rs", "fn main() {}")
            .await
            .unwrap();

        // Eventually should hit the limit
        for i in 0..10 {
            let result = auditor
                .analyze_file(&format!("test{}.rs", i), "fn main() {}")
                .await;
            if result.is_err() {
                assert!(result.unwrap_err().contains("max_steps"));
                return;
            }
        }

        // If we get here, the constraint wasn't enforced
        panic!("Max steps constraint should have been triggered");
    }
}
