// Properties of labels.cedar under labels.cedarschema (docs/adr/0009,
// docs/adr/0016).

@property("restricted-tools-are-never-called")
@kind("ceiling")
permit (principal, action, resource)
when { !resource.restricted };

// The rule the labels exist for: no call that sends data outside is allowed
// on arguments that may hold anything untrusted.
@property("untrusted-arguments-never-leave")
@kind("ceiling")
permit (principal, action, resource)
when { !(resource.external && context.labels.integrity == "untrusted") };

// Mail with readers reaches only those readers. A property that mentions
// `context.arguments` must be scoped to the action that has them.
@property("private-mail-reaches-only-its-readers")
@kind("ceiling")
permit (principal, action == Vak::Action::"call", resource);

@property("private-mail-reaches-only-its-readers")
@kind("ceiling")
permit (principal, action == Vak::Action::"send_email", resource)
when {
  context.labels.public || context.labels.readers.contains(context.arguments.to)
};

// And the rules don't over-reach: trusted, public mail to anyone still goes.
@property("trusted-public-mail-goes")
@kind("floor")
permit (principal, action == Vak::Action::"send_email", resource)
when {
  !resource.restricted &&
  context.labels.integrity == "trusted" &&
  context.labels.public
};
