// The tool-call rules of policies/default_policies.yaml, in Cedar
// (docs/adr/0008). `tests/cedar_policy.rs` checks that both decide every
// tool call the same way.
//
// The YAML file's file, network and memory rules govern actions the kernel
// doesn't decide through this adapter (host functions inside the sandbox),
// so they aren't ported here.
//
// Cedar denies anything no policy permits, and a forbid overrides any permit.

@id("forbid-dangerous-tools")
forbid (principal, action in Vak::Action::"call", resource == Vak::Tool::"rm -rf");

@id("forbid-dd")
forbid (principal, action in Vak::Action::"call", resource == Vak::Tool::"dd");

@id("forbid-mkfs")
forbid (principal, action in Vak::Action::"call", resource == Vak::Tool::"mkfs");

// Tools in `security.blocked_tools` are `restricted`.
@id("permit-safe-tools")
permit (principal, action in Vak::Action::"call", resource)
when { !resource.restricted };
