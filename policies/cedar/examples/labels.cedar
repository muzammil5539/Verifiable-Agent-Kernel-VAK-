// Information-flow rules over context.labels (docs/adr/0014, docs/adr/0016).
// labels.properties.cedar states what they guarantee.

@id("restricted-tools-never")
forbid (principal, action, resource)
when { resource.restricted };

@id("permit-unrestricted-tools")
permit (principal, action, resource)
when { !resource.restricted };

// Once an agent has read something untrusted, nothing it does may send data
// outside.
@id("no-external-call-on-untrusted-arguments")
forbid (principal, action, resource)
when { resource.external && context.labels.integrity == "untrusted" };

// Data with readers goes only to one of them.
@id("email-only-to-allowed-readers")
forbid (principal, action == Vak::Action::"send_email", resource)
unless {
  context.labels.public || context.labels.readers.contains(context.arguments.to)
};
