// Properties of payments.cedar under payments.cedarschema (docs/adr/0009).

@property("restricted-tools-are-never-called")
@kind("ceiling")
permit (principal, action, resource)
when { !resource.restricted };

// Only transfers of 0 to 1000, and only by finance agents. A ceiling that
// mentions `context.arguments` must be scoped to the action that has them.
@property("transfers-are-small-and-by-finance")
@kind("ceiling")
permit (principal, action == Vak::Action::"call", resource);

@property("transfers-are-small-and-by-finance")
@kind("ceiling")
permit (principal, action == Vak::Action::"transfer_funds", resource)
when {
  principal has team &&
  principal.team == "finance" &&
  context.arguments.amount >= 0 &&
  context.arguments.amount <= 1000
};
