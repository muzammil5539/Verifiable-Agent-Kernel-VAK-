# Neuro-Symbolic Reasoning Agent

## Project Overview

**Verifiable Agent Kernel (VAK)** implements neuro-symbolic reasoning to verify agent behavior. This agent manages the reasoning engine, Datalog rules, PRM scoring, and formal verification.

## Task Description

Manage the VAK reasoning system including:
- Datalog rule engine
- Safety rules and invariants
- Process Reward Model (PRM) integration
- Formal verification gateway
- Constraint verification

## Available Commands

```bash
# Test reasoner modules
cargo test --package vak --lib reasoner

# Run verification examples
cargo run --example verify_plan

# Benchmark reasoning
cargo bench reasoner
```

## Files This Agent Can Modify

### Reasoner Implementation
- `src/reasoner/mod.rs` - Module root
- `src/reasoner/datalog.rs` - Datalog engine
- `src/reasoner/prm.rs` - Process Reward Model
- `src/reasoner/verifier.rs` - Constraint verification
- `src/reasoner/verification_gateway.rs` - High-stakes verification
- `src/reasoner/tot.rs` - Tree of Thoughts

## Neuro-Symbolic Architecture

```
┌─────────────────────────────────────────────────────┐
│                   LLM Proposes Plan                  │
│              (Neural - Probabilistic)                │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────┐
│              Datalog Validates Plan                  │
│            (Symbolic - Deterministic)                │
│                                                      │
│  Rules:                                              │
│  - Malicious(X) <- FileAccess(X, "/etc/shadow")     │
│  - DenyNetwork(X) <- RiskScore(X, R), R > 0.7       │
└─────────────────────┬───────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
    ┌──────────┐           ┌──────────┐
    │ APPROVED │           │ REJECTED │
    │ Execute  │           │ Backtrack│
    └──────────┘           └──────────┘
```

## Datalog Implementation

### Rule Engine
```rust
use std::collections::{HashMap, HashSet};

pub struct DatalogEngine {
    facts: HashSet<Fact>,
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Fact {
    FileAccess(String, String),      // (agent, path)
    NetworkAccess(String, String),   // (agent, endpoint)
    RiskScore(String, u32),          // (agent, score 0-100)
    CriticalFile(String),            // (path)
    DeleteAction(String, String),    // (agent, target)
}

pub struct Rule {
    head: FactPattern,
    body: Vec<Condition>,
}

impl DatalogEngine {
    pub fn add_fact(&mut self, fact: Fact) {
        self.facts.insert(fact);
    }

    pub fn derive(&self) -> HashSet<Fact> {
        let mut derived = self.facts.clone();
        let mut changed = true;
        
        while changed {
            changed = false;
            for rule in &self.rules {
                for new_fact in rule.apply(&derived) {
                    if derived.insert(new_fact) {
                        changed = true;
                    }
                }
            }
        }
        
        derived
    }

    pub fn check_violations(&self) -> Vec<Violation> {
        let derived = self.derive();
        
        derived
            .iter()
            .filter_map(|fact| match fact {
                Fact::Malicious(agent) => Some(Violation::Malicious(agent.clone())),
                Fact::DenyNetwork(agent) => Some(Violation::NetworkDenied(agent.clone())),
                _ => None,
            })
            .collect()
    }
}
```

### Safety Rules
```rust
impl DatalogEngine {
    pub fn add_default_safety_rules(&mut self) {
        // Rule 1: Accessing /etc/shadow is malicious
        self.add_rule(Rule {
            head: FactPattern::Malicious(Var("X")),
            body: vec![
                Condition::Match(FactPattern::FileAccess(Var("X"), Const("/etc/shadow"))),
            ],
        });

        // Rule 2: Deleting critical files is a violation
        self.add_rule(Rule {
            head: FactPattern::Violation(Var("X")),
            body: vec![
                Condition::Match(FactPattern::DeleteAction(Var("X"), Var("Target"))),
                Condition::Match(FactPattern::CriticalFile(Var("Target"))),
            ],
        });

        // Rule 3: High risk agents cannot access network
        self.add_rule(Rule {
            head: FactPattern::DenyNetwork(Var("X")),
            body: vec![
                Condition::Match(FactPattern::RiskScore(Var("X"), Var("R"))),
                Condition::Compare(Var("R"), Op::Gt, Const(70)),
            ],
        });

        // Rule 4: External network access increases risk
        self.add_rule(Rule {
            head: FactPattern::HighRisk(Var("X")),
            body: vec![
                Condition::Match(FactPattern::NetworkAccess(Var("X"), Var("E"))),
                Condition::NotMatch(FactPattern::InternalEndpoint(Var("E"))),
            ],
        });
    }
}
```

### Process Reward Model
```rust
pub struct ProcessRewardModel {
    scorer: Box<dyn ReasoningScorer>,
    threshold: f64,
}

pub struct ReasoningStep {
    pub thought: String,
    pub action: Option<Action>,
    pub confidence: f64,
}

impl ProcessRewardModel {
    pub fn score_step(&self, step: &ReasoningStep) -> Result<StepScore, PrmError> {
        let score = self.scorer.score(&step.thought)?;
        
        Ok(StepScore {
            logic_score: score.logic,
            safety_score: score.safety,
            relevance_score: score.relevance,
            overall: (score.logic + score.safety + score.relevance) / 3.0,
        })
    }

    pub fn should_proceed(&self, step: &ReasoningStep) -> Result<Decision, PrmError> {
        let score = self.score_step(step)?;
        
        if score.overall >= self.threshold {
            Ok(Decision::Proceed)
        } else if score.safety_score < 0.5 {
            Ok(Decision::Reject { reason: "Safety concern".into() })
        } else {
            Ok(Decision::Backtrack { 
                reason: format!("Score {} below threshold {}", score.overall, self.threshold)
            })
        }
    }
}
```

### Verification Gateway
```rust
pub struct VerificationGateway {
    datalog: DatalogEngine,
    prm: ProcessRewardModel,
    high_stakes_actions: HashSet<ActionType>,
}

impl VerificationGateway {
    pub fn verify_action(&self, action: &ProposedAction) -> Result<VerificationResult, GatewayError> {
        // Step 1: Convert action to facts
        let facts = action.to_facts();
        
        // Step 2: Add facts to a fresh engine
        let mut engine = self.datalog.clone();
        for fact in facts {
            engine.add_fact(fact);
        }
        
        // Step 3: Check for violations
        let violations = engine.check_violations();
        if !violations.is_empty() {
            return Ok(VerificationResult::Denied {
                violations,
                reason: "Symbolic verification failed".into(),
            });
        }
        
        // Step 4: For high-stakes, also run PRM
        if self.high_stakes_actions.contains(&action.action_type) {
            let step = action.to_reasoning_step();
            match self.prm.should_proceed(&step)? {
                Decision::Reject { reason } => {
                    return Ok(VerificationResult::Denied {
                        violations: vec![],
                        reason,
                    });
                }
                Decision::Backtrack { reason } => {
                    return Ok(VerificationResult::Backtrack { reason });
                }
                Decision::Proceed => {}
            }
        }
        
        Ok(VerificationResult::Approved)
    }
}
```

## Guardrails

### DO
- Define clear, testable safety rules
- Use deterministic logic for safety checks
- Log all verification decisions
- Provide actionable feedback on rejections
- Support backtracking with alternatives
- Cache verification results when safe

### DON'T
- Trust LLM output without verification
- Skip verification for "simple" actions
- Use probabilistic checks for safety-critical decisions
- Allow rules to be modified by agents
- Ignore low confidence scores
- Short-circuit verification for performance

### Safety Requirements
- All high-stakes actions must be verified
- Violations must block execution
- Backtracking must be supported
- Verification must be deterministic

## Testing Patterns

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malicious_file_access() {
        let mut engine = DatalogEngine::new();
        engine.add_default_safety_rules();
        
        engine.add_fact(Fact::FileAccess("agent-1".into(), "/etc/shadow".into()));
        
        let violations = engine.check_violations();
        assert!(violations.iter().any(|v| matches!(v, Violation::Malicious(_))));
    }

    #[test]
    fn test_high_risk_network_block() {
        let mut engine = DatalogEngine::new();
        engine.add_default_safety_rules();
        
        engine.add_fact(Fact::RiskScore("agent-1".into(), 85));
        engine.add_fact(Fact::NetworkAccess("agent-1".into(), "external.com".into()));
        
        let violations = engine.check_violations();
        assert!(violations.iter().any(|v| matches!(v, Violation::NetworkDenied(_))));
    }

    #[test]
    fn test_safe_action_approved() {
        let gateway = VerificationGateway::new();
        
        let action = ProposedAction {
            action_type: ActionType::FileRead,
            target: "/data/report.csv".into(),
            agent_id: "agent-1".into(),
        };
        
        let result = gateway.verify_action(&action).unwrap();
        assert!(matches!(result, VerificationResult::Approved));
    }
}
```

## Related Agents
- [Rust Code Generator Agent](Rust Code Generator Agent.agent.md)
- [Policy Engine Agent](Policy Engine Agent.agent.md)
- [WASM Sandbox Agent](WASM Sandbox Agent.agent.md)