---
name: vak-policy
description: Check if an action is allowed by policy. Use this to verify permissions before attempting to execute a tool.
allowed-tools: python
---

# VAK Policy Check Skill

This skill allows you to verify if an action is permitted by the current Verifiable Agent Kernel (VAK) policies. This is useful for pre-checking permissions before executing potentially disruptive or expensive tools.

## Usage

Run the `check_policy.py` script to evaluate policies. The script will automatically install the VAK SDK if it is missing.

### Basic Usage

To check if an action is allowed:

```bash
python .github/skills/vak-policy/check_policy.py \
  --agent-id "my-agent" \
  --action "tool.execute" \
  --resource "calculator"
```

### With Context

You can provide additional context for policy decisions (e.g., tool parameters, environment details):

```bash
python .github/skills/vak-policy/check_policy.py \
  --agent-id "finance-agent" \
  --action "payment.process" \
  --resource "account-123" \
  --context '{"amount": 500, "currency": "USD"}'
```

## Output

The script outputs a JSON object with the policy decision:

```json
{
  "allowed": true,
  "effect": "allow",
  "policy_id": "finance-allow-small-payments",
  "reason": "Payment under $1000 is allowed",
  "matched_rules": ["rule-123"]
}
```

If the action is denied, the script will exit with a non-zero status code.
