// Properties of policies/cedar/default.cedar, proved with SymCC
// (docs/adr/0009). CI runs:
//
//   cargo run --example cedar_check --features cedar-analysis -- \
//     --policies policies/cedar --properties policies/cedar/properties
//
// A ceiling bounds what the policies may allow: every request they allow,
// the ceiling must allow too. A floor is what they must keep allowing.
// Policies sharing a @property name form one property.
//
// The checks cover every request and entity store the schema admits, not
// only the tools that exist. So a floor naming tools by id, as below, is
// stronger than one that trusts `resource.builtin`: a policy set may
// legitimately forbid a tool called "dd" even if something marks it built-in.

@property("restricted-tools-are-never-called")
@kind("ceiling")
permit (principal, action, resource)
when { !resource.restricted };

@property("dangerous-tools-are-never-called")
@kind("ceiling")
permit (principal, action, resource)
unless { [Vak::Tool::"rm -rf", Vak::Tool::"dd", Vak::Tool::"mkfs"].contains(resource) };

@property("unrestricted-builtins-stay-callable")
@kind("floor")
permit (principal, action == Vak::Action::"call", resource)
when {
  [
    Vak::Tool::"echo",
    Vak::Tool::"calculator",
    Vak::Tool::"data_processor",
    Vak::Tool::"system_info"
  ].contains(resource) &&
  !resource.restricted
};
