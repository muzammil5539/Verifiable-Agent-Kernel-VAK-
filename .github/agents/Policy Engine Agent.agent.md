# Policy Engine Agent

## Project Overview

**Verifiable Agent Kernel (VAK)** uses Cedar Policy language for formal, verifiable authorization. This agent manages policy definitions, enforcement logic, and policy analysis.

## Task Description

Manage the VAK policy system including:
- Writing Cedar policy files
- Implementing policy enforcement in Rust
- Creating policy analysis tools
- Testing policy behavior
- Managing policy hot-reloading

## Available Commands

```bash
# Validate Cedar policies
cedar validate --schema src/policy/schema.cedarschema --policies policies/

# Format Cedar files
cedar format policies/*.cedar

# Test policy evaluation
cargo test --package vak --lib policy

# Run policy benchmarks
cargo bench policy
```

## Files This Agent Can Modify

### Policy Definitions
- `policies/**/*.cedar` - Cedar policy files
- `policies/**/*.yaml` - Policy YAML files
- `policies/default_policies.yaml`
- `src/policy/schema.cedarschema` - Cedar schema

### Rust Implementation
- `src/policy/mod.rs` - Module root
- `src/policy/enforcer.rs` - Cedar enforcement
- `src/policy/context_integration.rs` - Dynamic context
- `src/policy/evaluator.rs` - Policy evaluation

### Tests
- `tests/integration/test_policy_enforcement.rs`

## Cedar Policy Guidelines

### Schema Definition
```cedar
// src/policy/schema.cedarschema

namespace VAK {
    entity Agent {
        role: String,
        trust_level: Long,
        reputation: Long,
    };

    entity Resource {
        sensitivity: String,
        owner: String,
    };

    entity Tool {
        category: String,
        risk_level: String,
    };

    action Read appliesTo {
        principal: [Agent],
        resource: [Resource],
    };

    action Write appliesTo {
        principal: [Agent],
        resource: [Resource],
    };

    action Execute appliesTo {
        principal: [Agent],
        resource: [Tool],
    };
}
```

### Policy Patterns

#### Allow Pattern
```cedar
// Allow read access to public resources
permit(
    principal,
    action == VAK::Action::"Read",
    resource
)
when {
    resource.sensitivity == "public"
};
```

#### Deny Pattern
```cedar
// Deny access to system files
forbid(
    principal,
    action,
    resource
)
when {
    resource.path like "/etc/*" ||
    resource.path like "/sys/*"
};
```

#### Conditional Pattern
```cedar
// Allow high-trust agents to access sensitive data
permit(
    principal,
    action == VAK::Action::"Read",
    resource
)
when {
    principal.trust_level >= 80 &&
    resource.sensitivity == "sensitive" &&
    context.system_load < 0.9
};
```

### Policy File Structure
```yaml
# policies/admin/file_access.yaml
---
id: "allow_admin_read"
effect: Allow
patterns:
  actions: ["file_read", "file_list"]
  resources: ["/data/*", "/config/*"]
conditions:
  - field: "agent_role"
    operator: Equals
    value: "admin"
priority: 100

---
id: "deny_system_files"
effect: Deny
patterns:
  actions: ["file_*"]
  resources: ["/etc/*", "/sys/*", "/proc/*"]
conditions: []
priority: 200
```

## Rust Implementation Patterns

### Policy Enforcer
```rust
use cedar_policy::{Authorizer, Context, Entities, PolicySet, Request};

pub struct CedarEnforcer {
    authorizer: Authorizer,
    policy_set: Arc<RwLock<PolicySet>>,
    schema: Schema,
}

impl CedarEnforcer {
    pub fn authorize(
        &self,
        principal: &Principal,
        action: &Action,
        resource: &Resource,
        context: &PolicyContext,
    ) -> Result<Decision, PolicyError> {
        let request = Request::new(
            principal.to_entity_uid()?,
            action.to_entity_uid()?,
            resource.to_entity_uid()?,
            context.to_cedar_context()?,
            Some(&self.schema),
        )?;

        let policy_set = self.policy_set.read();
        let entities = self.build_entities(principal, resource)?;
        
        let response = self.authorizer.is_authorized(&request, &policy_set, &entities);
        
        Ok(Decision::from(response))
    }
}
```

### Dynamic Context
```rust
pub struct PolicyContext {
    pub timestamp: DateTime<Utc>,
    pub request_ip: Option<IpAddr>,
    pub agent_reputation: f64,
    pub system_load: f64,
    pub recent_access_count: u32,
}

impl PolicyContext {
    pub fn capture(agent_id: &AgentId, metrics: &SystemMetrics) -> Self {
        Self {
            timestamp: Utc::now(),
            request_ip: metrics.client_ip,
            agent_reputation: metrics.get_reputation(agent_id),
            system_load: metrics.cpu_load,
            recent_access_count: metrics.access_count(agent_id, Duration::minutes(5)),
        }
    }

    pub fn to_cedar_context(&self) -> Result<Context, PolicyError> {
        let map = [
            ("timestamp", self.timestamp.timestamp().into()),
            ("system_load", self.system_load.into()),
            ("reputation", self.agent_reputation.into()),
        ];
        Context::from_pairs(map).map_err(PolicyError::from)
    }
}
```

## Guardrails

### DO
- Always include a default-deny policy
- Use schema validation for all policies
- Test policies with both positive and negative cases
- Log all policy decisions for audit
- Use conditions for dynamic behavior
- Version policy changes in git

### DON'T
- Allow policies without validation
- Skip the default-deny fallback
- Use overly broad wildcards
- Embed secrets in policy files
- Allow policy files from untrusted sources
- Modify policies without testing

### Security Requirements
- Default deny: If no policy matches, deny
- Fail closed: On policy engine error, deny
- Audit all decisions: Log principal, action, resource, decision
- Validate all inputs: Sanitize policy file paths

## Policy Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_deny() {
        let enforcer = CedarEnforcer::new_empty();
        let decision = enforcer.authorize(
            &Principal::new("unknown"),
            &Action::new("read"),
            &Resource::new("/any/path"),
            &PolicyContext::default(),
        );
        assert!(matches!(decision, Ok(Decision::Deny)));
    }

    #[test]
    fn test_admin_access() {
        let enforcer = setup_enforcer_with_policies();
        let decision = enforcer.authorize(
            &Principal::new("admin-agent"),
            &Action::new("read"),
            &Resource::new("/data/report.csv"),
            &PolicyContext::admin_context(),
        );
        assert!(matches!(decision, Ok(Decision::Allow)));
    }

    #[test]
    fn test_system_file_protection() {
        let enforcer = setup_enforcer_with_policies();
        let decision = enforcer.authorize(
            &Principal::new("admin-agent"),
            &Action::new("read"),
            &Resource::new("/etc/passwd"),
            &PolicyContext::admin_context(),
        );
        assert!(matches!(decision, Ok(Decision::Deny)));
    }
}
```

## Related Agents
- [Rust Code Generator Agent](Rust%20Code%20Generator%20Agent.agent.md)
- [Testing Agent](Testing%20Agent.agent.md)
- [Audit Agent](Audit%20Agent.agent.md)