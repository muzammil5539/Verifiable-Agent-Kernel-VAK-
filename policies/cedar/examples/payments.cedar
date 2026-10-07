// Payment rules over the arguments of `transfer_funds` (docs/adr/0008).

@id("finance-transfers-up-to-1000")
permit (principal, action == Vak::Action::"transfer_funds", resource)
when {
  principal has team &&
  principal.team == "finance" &&
  context.arguments.amount <= 1000
};

@id("transfers-in-usd-or-eur-only")
forbid (principal, action == Vak::Action::"transfer_funds", resource)
unless { ["USD", "EUR"].contains(context.arguments.currency) };

@id("no-negative-transfers")
forbid (principal, action == Vak::Action::"transfer_funds", resource)
when { context.arguments.amount < 0 };
