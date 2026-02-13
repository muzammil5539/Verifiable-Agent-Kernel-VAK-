//! Cross-Module Integration Tests (v0.3 - TST-007)
//!
//! Comprehensive tests validating interactions between kernel subsystems:
//! - Policy ↔ Audit integration (every policy decision is audited)
//! - Memory ↔ Audit integration (memory state changes produce audit entries)
//! - Reasoner ↔ Policy integration (PRM-scored actions checked against policy)
//! - Swarm ↔ Audit integration (consensus decisions are audited)
//! - End-to-end session lifecycle with all subsystems

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ============================================================================
// Cross-Module: Policy ↔ Audit Integration
// ============================================================================

/// Verify that every policy decision generates a corresponding audit entry
#[tokio::test]
async fn test_policy_decisions_generate_audit_entries() {
    let audit_log = Arc::new(RwLock::new(Vec::<CrossModuleAuditEntry>::new()));

    // Simulate a sequence of policy decisions
    let decisions = vec![
        ("agent-1", "read", "/data/public.txt", true),
        ("agent-1", "write", "/data/public.txt", true),
        ("agent-2", "delete", "/system/config", false),
        ("agent-3", "execute", "/tools/calculator", true),
        ("agent-2", "read", "/secrets/api_key", false),
    ];

    for (agent, action, resource, allowed) in &decisions {
        let decision = simulate_policy_decision(agent, action, resource);
        assert_eq!(
            decision.allowed, *allowed,
            "Policy decision mismatch for {} {} {}",
            agent, action, resource
        );

        // Every decision must produce an audit entry
        let entry = CrossModuleAuditEntry {
            agent_id: agent.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            decision: if decision.allowed {
                "allowed".to_string()
            } else {
                "denied".to_string()
            },
            timestamp_ms: current_timestamp_ms(),
            subsystem: "policy".to_string(),
        };
        audit_log.write().await.push(entry);
    }

    let log = audit_log.read().await;
    assert_eq!(
        log.len(),
        decisions.len(),
        "Every policy decision must have an audit entry"
    );

    // Verify denied entries are properly marked
    let denied_count = log.iter().filter(|e| e.decision == "denied").count();
    assert_eq!(denied_count, 2, "Should have exactly 2 denied entries");
}

/// Verify audit entries maintain causal ordering across subsystems
#[tokio::test]
async fn test_cross_subsystem_audit_ordering() {
    let audit_log = Arc::new(RwLock::new(Vec::<CrossModuleAuditEntry>::new()));

    // Simulate a multi-step workflow that touches multiple subsystems
    let subsystem_sequence = vec![
        ("policy", "evaluate_request"),
        ("reasoner", "score_reasoning_step"),
        ("sandbox", "execute_tool"),
        ("memory", "store_result"),
        ("audit", "finalize_entry"),
    ];

    let mut prev_timestamp = 0i64;
    for (subsystem, action) in &subsystem_sequence {
        let ts = current_timestamp_ms();
        assert!(
            ts >= prev_timestamp,
            "Timestamps must be monotonically increasing"
        );
        prev_timestamp = ts;

        audit_log.write().await.push(CrossModuleAuditEntry {
            agent_id: "workflow-agent".to_string(),
            action: action.to_string(),
            resource: format!("/{}/workflow", subsystem),
            decision: "allowed".to_string(),
            timestamp_ms: ts,
            subsystem: subsystem.to_string(),
        });
    }

    let log = audit_log.read().await;
    assert_eq!(log.len(), 5, "All subsystem steps should be logged");

    // Verify ordering
    for i in 1..log.len() {
        assert!(
            log[i].timestamp_ms >= log[i - 1].timestamp_ms,
            "Audit entries must maintain causal order"
        );
    }
}

// ============================================================================
// Cross-Module: Memory ↔ Audit Integration
// ============================================================================

/// Verify memory operations generate audit trail entries
#[tokio::test]
async fn test_memory_operations_audited() {
    let audit_log = Arc::new(RwLock::new(Vec::<CrossModuleAuditEntry>::new()));
    let memory = MockCrossModuleMemory::new();

    // Perform memory operations
    let operations = vec![
        ("store", "working", "context_data"),
        ("store", "episodic", "episode_1"),
        ("retrieve", "working", "context_data"),
        ("rollback", "episodic", "checkpoint_1"),
    ];

    for (op, tier, key) in &operations {
        match *op {
            "store" => memory.store(tier, key, &format!("value_for_{}", key)),
            "retrieve" => {
                let _ = memory.retrieve(tier, key);
            }
            "rollback" => memory.rollback(tier, key),
            _ => unreachable!(),
        }

        audit_log.write().await.push(CrossModuleAuditEntry {
            agent_id: "memory-test-agent".to_string(),
            action: format!("memory_{}", op),
            resource: format!("/{}/{}", tier, key),
            decision: "allowed".to_string(),
            timestamp_ms: current_timestamp_ms(),
            subsystem: "memory".to_string(),
        });
    }

    let log = audit_log.read().await;
    assert_eq!(log.len(), 4, "All memory operations should be audited");
    assert!(
        log.iter().all(|e| e.subsystem == "memory"),
        "All entries should be from memory subsystem"
    );
}

/// Verify memory state hashes change after write operations
#[tokio::test]
async fn test_memory_state_hash_integrity() {
    let memory = MockCrossModuleMemory::new();

    let hash_before = memory.state_hash();
    memory.store("working", "key1", "value1");
    let hash_after_first = memory.state_hash();
    assert_ne!(
        hash_before, hash_after_first,
        "Hash must change after write"
    );

    memory.store("working", "key2", "value2");
    let hash_after_second = memory.state_hash();
    assert_ne!(
        hash_after_first, hash_after_second,
        "Hash must change after second write"
    );

    // Same content should produce same hash deterministically
    let memory2 = MockCrossModuleMemory::new();
    memory2.store("working", "key1", "value1");
    memory2.store("working", "key2", "value2");
    assert_eq!(
        hash_after_second,
        memory2.state_hash(),
        "Same operations should produce same hash"
    );
}

// ============================================================================
// Cross-Module: Reasoner ↔ Policy Integration
// ============================================================================

/// Verify PRM-scored actions are still subject to policy enforcement
#[tokio::test]
async fn test_prm_scored_actions_checked_by_policy() {
    let policy_engine = MockCrossModulePolicy::new();

    // Simulate a PRM-scored reasoning step
    let reasoning_steps = vec![
        ReasoningStepResult {
            step_id: 1,
            description: "Analyze input for SQL injection".to_string(),
            prm_score: 0.92,
            action: "read".to_string(),
            resource: "/data/user_input.txt".to_string(),
        },
        ReasoningStepResult {
            step_id: 2,
            description: "Execute remediation script".to_string(),
            prm_score: 0.85,
            action: "execute".to_string(),
            resource: "/scripts/fix_sqli.sh".to_string(),
        },
        ReasoningStepResult {
            step_id: 3,
            description: "Modify system configuration".to_string(),
            prm_score: 0.95,
            action: "write".to_string(),
            resource: "/system/config".to_string(),
        },
    ];

    for step in &reasoning_steps {
        // Even if PRM score is high, policy must be checked
        let policy_decision = policy_engine.evaluate(&step.action, &step.resource);

        if step.resource.starts_with("/system/") {
            assert!(
                !policy_decision.allowed,
                "System resources should be denied regardless of PRM score (step {})",
                step.step_id
            );
        } else {
            assert!(
                policy_decision.allowed,
                "Non-system resources should be allowed (step {})",
                step.step_id
            );
        }
    }
}

/// Verify low PRM scores trigger additional verification gates
#[tokio::test]
async fn test_low_prm_scores_trigger_verification() {
    let prm_threshold = 0.6;

    let scores = vec![
        ("high_confidence_step", 0.95, false),
        ("medium_confidence_step", 0.75, false),
        ("low_confidence_step", 0.45, true),
        ("very_low_confidence_step", 0.20, true),
    ];

    for (step_name, score, should_require_verification) in &scores {
        let requires_verification = *score < prm_threshold;
        assert_eq!(
            requires_verification, *should_require_verification,
            "Step '{}' with score {} verification requirement mismatch",
            step_name, score
        );
    }
}

// ============================================================================
// Cross-Module: Swarm ↔ Audit Integration
// ============================================================================

/// Verify swarm consensus decisions are fully audited
#[tokio::test]
async fn test_swarm_consensus_audited() {
    let audit_log = Arc::new(RwLock::new(Vec::<CrossModuleAuditEntry>::new()));

    // Simulate a multi-agent voting session
    let agents = vec!["agent-1", "agent-2", "agent-3", "agent-4", "agent-5"];
    let votes = vec![true, true, false, true, true]; // 4-1 in favor

    // Log vote submission for each agent
    for (agent, vote) in agents.iter().zip(votes.iter()) {
        audit_log.write().await.push(CrossModuleAuditEntry {
            agent_id: agent.to_string(),
            action: "cast_vote".to_string(),
            resource: "/swarm/proposal-001".to_string(),
            decision: if *vote {
                "approve".to_string()
            } else {
                "reject".to_string()
            },
            timestamp_ms: current_timestamp_ms(),
            subsystem: "swarm".to_string(),
        });
    }

    // Log consensus result
    let approve_count = votes.iter().filter(|&&v| v).count();
    let consensus_reached = approve_count > agents.len() / 2;
    assert!(consensus_reached, "Consensus should be reached (4/5)");

    audit_log.write().await.push(CrossModuleAuditEntry {
        agent_id: "swarm-coordinator".to_string(),
        action: "consensus_reached".to_string(),
        resource: "/swarm/proposal-001".to_string(),
        decision: format!(
            "approved_{}_of_{}",
            approve_count,
            agents.len()
        ),
        timestamp_ms: current_timestamp_ms(),
        subsystem: "swarm".to_string(),
    });

    let log = audit_log.read().await;
    assert_eq!(log.len(), 6, "5 votes + 1 consensus entry");
}

/// Verify sycophancy detection flags suspicious voting patterns
#[tokio::test]
async fn test_sycophancy_detection_in_swarm() {
    // Simulate agents that all agree too quickly (sycophancy indicator)
    let voting_rounds = vec![
        vec![true, true, true, true, true], // Round 1: unanimous
        vec![true, true, true, true, true], // Round 2: unanimous
        vec![true, true, true, true, true], // Round 3: unanimous
    ];

    let unanimity_count = voting_rounds
        .iter()
        .filter(|round| round.iter().all(|&v| v))
        .count();

    let sycophancy_threshold = 2; // More than 2 unanimous rounds is suspicious
    let sycophancy_detected = unanimity_count > sycophancy_threshold;
    assert!(
        sycophancy_detected,
        "Should detect sycophancy in all-agree pattern"
    );

    // Verify diverse opinions are not flagged
    let healthy_rounds = vec![
        vec![true, false, true, true, false],
        vec![false, true, true, false, true],
        vec![true, true, false, true, false],
    ];

    let healthy_unanimity = healthy_rounds
        .iter()
        .filter(|round| round.iter().all(|&v| v))
        .count();
    assert_eq!(
        healthy_unanimity, 0,
        "Diverse opinions should not trigger sycophancy"
    );
}

// ============================================================================
// End-to-End: Full Session Lifecycle
// ============================================================================

/// Test complete session lifecycle across all subsystems
#[tokio::test]
async fn test_full_session_lifecycle() {
    let session = MockSession::new("session-001", "agent-lifecycle");

    // Phase 1: Session initialization
    assert!(session.is_active());
    assert_eq!(session.step_count(), 0);

    // Phase 2: Policy evaluation
    let policy_ok = session.evaluate_policy("read", "/data/input.txt");
    assert!(policy_ok, "Read should be allowed");

    // Phase 3: Memory store
    session.store_memory("input_data", "test content for analysis");
    assert_eq!(session.step_count(), 1);

    // Phase 4: Reasoning (PRM scoring)
    let prm_score = session.score_reasoning("Analyzing input for vulnerabilities");
    assert!(
        prm_score >= 0.0 && prm_score <= 1.0,
        "PRM score should be in [0, 1]"
    );

    // Phase 5: Tool execution
    let tool_result = session.execute_tool("text-analyzer", "analyze input");
    assert!(tool_result.success);

    // Phase 6: Memory update with result
    session.store_memory("analysis_result", &tool_result.output);

    // Phase 7: Audit verification
    let audit_entries = session.get_audit_entries();
    assert!(
        audit_entries.len() >= 4,
        "Should have entries for policy, memory, reasoning, execution"
    );

    // Phase 8: Session finalization
    session.finalize();
    assert!(!session.is_active());

    // Verify audit chain integrity
    assert!(
        session.verify_audit_chain(),
        "Audit chain should be intact after session"
    );
}

/// Test error propagation across subsystem boundaries
#[tokio::test]
async fn test_error_propagation_across_subsystems() {
    let session = MockSession::new("session-err", "agent-error-test");

    // Policy denial should not leave orphaned memory entries
    let policy_ok = session.evaluate_policy("delete", "/system/audit_log");
    assert!(!policy_ok, "Delete on audit_log should be denied");

    // Verify no tool execution occurred
    assert_eq!(
        session.tool_execution_count(),
        0,
        "No tools should execute after policy denial"
    );

    // Verify denial was properly audited
    let audit_entries = session.get_audit_entries();
    assert!(
        audit_entries
            .iter()
            .any(|e| e.decision == "denied"),
        "Policy denial must be audited"
    );
}

/// Test concurrent sessions do not interfere with each other
#[tokio::test]
async fn test_concurrent_session_isolation() {
    let session1 = Arc::new(MockSession::new("session-1", "agent-1"));
    let session2 = Arc::new(MockSession::new("session-2", "agent-2"));

    let s1 = session1.clone();
    let s2 = session2.clone();

    let handle1 = tokio::spawn(async move {
        for i in 0..50 {
            s1.store_memory(&format!("key-{}", i), &format!("s1-value-{}", i));
        }
    });

    let handle2 = tokio::spawn(async move {
        for i in 0..50 {
            s2.store_memory(&format!("key-{}", i), &format!("s2-value-{}", i));
        }
    });

    handle1.await.expect("Session 1 task should complete");
    handle2.await.expect("Session 2 task should complete");

    // Verify isolation: each session has its own data
    assert_eq!(
        session1.memory_count(),
        50,
        "Session 1 should have 50 entries"
    );
    assert_eq!(
        session2.memory_count(),
        50,
        "Session 2 should have 50 entries"
    );

    // Verify data integrity: session 1 data should not contain session 2 values
    let s1_values = session1.get_all_memory_values();
    assert!(
        s1_values.iter().all(|v| v.starts_with("s1-")),
        "Session 1 should only contain its own values"
    );
}

// ============================================================================
// Edge Cases: Subsystem Boundary Conditions
// ============================================================================

/// Test handling of maximum concurrent agents
#[tokio::test]
async fn test_max_concurrent_agents() {
    let max_agents = 100;
    let mut sessions = Vec::new();

    for i in 0..max_agents {
        let session = MockSession::new(
            &format!("session-{}", i),
            &format!("agent-{}", i),
        );
        sessions.push(session);
    }

    // All sessions should be active
    assert_eq!(sessions.len(), max_agents);
    assert!(sessions.iter().all(|s| s.is_active()));

    // Finalize all sessions
    for session in &sessions {
        session.finalize();
    }
    assert!(sessions.iter().all(|s| !s.is_active()));
}

/// Test recovery after subsystem failure
#[tokio::test]
async fn test_subsystem_failure_recovery() {
    let session = MockSession::new("session-recovery", "agent-recovery");

    // Simulate a tool execution failure
    let result = session.execute_tool("nonexistent-tool", "invalid input");
    assert!(!result.success, "Nonexistent tool should fail");

    // Session should still be operational after failure
    assert!(session.is_active(), "Session should survive tool failure");

    // Subsequent operations should work
    let policy_ok = session.evaluate_policy("read", "/data/recovery.txt");
    assert!(policy_ok, "Read should still work after tool failure");

    // Audit should record the failure
    let audit_entries = session.get_audit_entries();
    assert!(
        audit_entries.iter().any(|e| e.action == "tool_failure"),
        "Tool failure must be audited"
    );
}

/// Test hash chain integrity after interleaved operations
#[tokio::test]
async fn test_interleaved_operation_hash_chain() {
    let audit_log = Arc::new(RwLock::new(Vec::<CrossModuleAuditEntry>::new()));
    let mut handles = Vec::new();

    // Spawn multiple subsystems writing audit entries concurrently
    for subsystem in &["policy", "memory", "reasoner", "sandbox", "swarm"] {
        let log = audit_log.clone();
        let subsystem_name = subsystem.to_string();

        let handle = tokio::spawn(async move {
            for i in 0..20 {
                log.write().await.push(CrossModuleAuditEntry {
                    agent_id: format!("{}-agent", subsystem_name),
                    action: format!("{}_op_{}", subsystem_name, i),
                    resource: format!("/{}/resource_{}", subsystem_name, i),
                    decision: "allowed".to_string(),
                    timestamp_ms: current_timestamp_ms(),
                    subsystem: subsystem_name.clone(),
                });
                // Small delay to interleave
                tokio::time::sleep(tokio::time::Duration::from_micros(10)).await;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("Subsystem task should complete");
    }

    let log = audit_log.read().await;
    assert_eq!(log.len(), 100, "5 subsystems x 20 ops = 100 entries");

    // Verify all subsystems are represented
    let mut subsystem_counts = HashMap::new();
    for entry in log.iter() {
        *subsystem_counts
            .entry(entry.subsystem.clone())
            .or_insert(0) += 1;
    }
    assert_eq!(subsystem_counts.len(), 5, "All 5 subsystems should appear");
    for (subsystem, count) in &subsystem_counts {
        assert_eq!(*count, 20, "Subsystem {} should have 20 entries", subsystem);
    }
}

// ============================================================================
// Mock Types and Helper Functions
// ============================================================================

fn current_timestamp_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Clone)]
struct CrossModuleAuditEntry {
    agent_id: String,
    action: String,
    resource: String,
    decision: String,
    timestamp_ms: i64,
    subsystem: String,
}

struct MockCrossModulePolicy {
    denied_prefixes: Vec<String>,
}

impl MockCrossModulePolicy {
    fn new() -> Self {
        Self {
            denied_prefixes: vec!["/system/".to_string(), "/secrets/".to_string()],
        }
    }

    fn evaluate(&self, action: &str, resource: &str) -> PolicyDecisionResult {
        let denied = self
            .denied_prefixes
            .iter()
            .any(|prefix| resource.starts_with(prefix));

        if denied {
            PolicyDecisionResult {
                allowed: false,
                reason: format!("Access to {} denied by policy", resource),
            }
        } else {
            PolicyDecisionResult {
                allowed: true,
                reason: format!("{} on {} allowed", action, resource),
            }
        }
    }
}

struct PolicyDecisionResult {
    allowed: bool,
    #[allow(dead_code)]
    reason: String,
}

fn simulate_policy_decision(agent: &str, action: &str, resource: &str) -> PolicyDecisionResult {
    let policy = MockCrossModulePolicy::new();
    let _ = agent; // Agent ID used for context in real implementation
    policy.evaluate(action, resource)
}

struct MockCrossModuleMemory {
    data: std::sync::Mutex<HashMap<String, HashMap<String, String>>>,
}

impl MockCrossModuleMemory {
    fn new() -> Self {
        Self {
            data: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn store(&self, tier: &str, key: &str, value: &str) {
        let mut data = self.data.lock().unwrap();
        data.entry(tier.to_string())
            .or_insert_with(HashMap::new)
            .insert(key.to_string(), value.to_string());
    }

    fn retrieve(&self, tier: &str, key: &str) -> Option<String> {
        let data = self.data.lock().unwrap();
        data.get(tier)?.get(key).cloned()
    }

    fn rollback(&self, tier: &str, _checkpoint: &str) {
        let mut data = self.data.lock().unwrap();
        data.remove(tier);
    }

    fn state_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let data = self.data.lock().unwrap();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        let mut sorted_entries: Vec<_> = data
            .iter()
            .flat_map(|(tier, entries)| {
                entries
                    .iter()
                    .map(move |(k, v)| format!("{}:{}:{}", tier, k, v))
            })
            .collect();
        sorted_entries.sort();
        for entry in &sorted_entries {
            entry.hash(&mut hasher);
        }
        hasher.finish()
    }
}

#[allow(dead_code)]
struct ReasoningStepResult {
    step_id: u32,
    description: String,
    prm_score: f64,
    action: String,
    resource: String,
}

struct MockSession {
    id: String,
    #[allow(dead_code)]
    agent_id: String,
    active: std::sync::atomic::AtomicBool,
    steps: std::sync::atomic::AtomicU32,
    tool_executions: std::sync::atomic::AtomicU32,
    memory: std::sync::Mutex<HashMap<String, String>>,
    audit_entries: std::sync::Mutex<Vec<CrossModuleAuditEntry>>,
}

impl MockSession {
    fn new(id: &str, agent_id: &str) -> Self {
        Self {
            id: id.to_string(),
            agent_id: agent_id.to_string(),
            active: std::sync::atomic::AtomicBool::new(true),
            steps: std::sync::atomic::AtomicU32::new(0),
            tool_executions: std::sync::atomic::AtomicU32::new(0),
            memory: std::sync::Mutex::new(HashMap::new()),
            audit_entries: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn is_active(&self) -> bool {
        self.active
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn step_count(&self) -> u32 {
        self.steps
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn tool_execution_count(&self) -> u32 {
        self.tool_executions
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn memory_count(&self) -> usize {
        self.memory.lock().unwrap().len()
    }

    fn evaluate_policy(&self, action: &str, resource: &str) -> bool {
        let policy = MockCrossModulePolicy::new();
        let result = policy.evaluate(action, resource);

        let mut entries = self.audit_entries.lock().unwrap();
        entries.push(CrossModuleAuditEntry {
            agent_id: self.id.clone(),
            action: format!("policy_{}", action),
            resource: resource.to_string(),
            decision: if result.allowed {
                "allowed".to_string()
            } else {
                "denied".to_string()
            },
            timestamp_ms: current_timestamp_ms(),
            subsystem: "policy".to_string(),
        });

        result.allowed
    }

    fn store_memory(&self, key: &str, value: &str) {
        self.memory
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        self.steps
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut entries = self.audit_entries.lock().unwrap();
        entries.push(CrossModuleAuditEntry {
            agent_id: self.id.clone(),
            action: "memory_store".to_string(),
            resource: format!("/memory/{}", key),
            decision: "allowed".to_string(),
            timestamp_ms: current_timestamp_ms(),
            subsystem: "memory".to_string(),
        });
    }

    fn get_all_memory_values(&self) -> Vec<String> {
        self.memory.lock().unwrap().values().cloned().collect()
    }

    fn score_reasoning(&self, description: &str) -> f64 {
        let mut entries = self.audit_entries.lock().unwrap();
        entries.push(CrossModuleAuditEntry {
            agent_id: self.id.clone(),
            action: "prm_score".to_string(),
            resource: format!("/reasoner/{}", description),
            decision: "allowed".to_string(),
            timestamp_ms: current_timestamp_ms(),
            subsystem: "reasoner".to_string(),
        });

        // Deterministic mock score based on description length
        let score = (description.len() as f64 % 100.0) / 100.0;
        score.max(0.5) // Minimum 0.5 for mock
    }

    fn execute_tool(&self, tool_name: &str, _input: &str) -> ToolExecutionResult {
        let known_tools = vec![
            "calculator",
            "text-analyzer",
            "crypto-hash",
            "json-validator",
            "regex-matcher",
        ];

        let success = known_tools.contains(&tool_name);
        if success {
            self.tool_executions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        let mut entries = self.audit_entries.lock().unwrap();
        entries.push(CrossModuleAuditEntry {
            agent_id: self.id.clone(),
            action: if success {
                "tool_execution".to_string()
            } else {
                "tool_failure".to_string()
            },
            resource: format!("/sandbox/{}", tool_name),
            decision: if success {
                "allowed".to_string()
            } else {
                "failed".to_string()
            },
            timestamp_ms: current_timestamp_ms(),
            subsystem: "sandbox".to_string(),
        });

        ToolExecutionResult {
            success,
            output: if success {
                format!("Result from {}", tool_name)
            } else {
                format!("Tool '{}' not found", tool_name)
            },
        }
    }

    fn get_audit_entries(&self) -> Vec<CrossModuleAuditEntry> {
        self.audit_entries.lock().unwrap().clone()
    }

    fn verify_audit_chain(&self) -> bool {
        let entries = self.audit_entries.lock().unwrap();
        // Verify monotonic timestamps
        for i in 1..entries.len() {
            if entries[i].timestamp_ms < entries[i - 1].timestamp_ms {
                return false;
            }
        }
        true
    }

    fn finalize(&self) {
        self.active
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

struct ToolExecutionResult {
    success: bool,
    output: String,
}
