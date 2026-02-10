---
name: vak-audit
description: Query and inspect audit logs from the Verifiable Agent Kernel (VAK). Use this when asked to show audit trails, check past actions, or verify compliance.
allowed-tools: python
---

# VAK Audit Skill

This skill allows you to query the audit logs of the Verifiable Agent Kernel (VAK). You can filter logs by agent ID, action type, audit level, or time range.

## Usage

Run the `audit.py` script to fetch audit logs. The script will automatically install the VAK SDK if it is missing.

### Basic Usage

To list the most recent audit logs:

```bash
python .github/skills/vak-audit/audit.py
```

### Filtering by Agent

To see actions performed by a specific agent:

```bash
python .github/skills/vak-audit/audit.py --agent-id "agent-123"
```

### Filtering by Action

To see specific actions (supports wildcards):

```bash
python .github/skills/vak-audit/audit.py --action "tool.execute"
python .github/skills/vak-audit/audit.py --action "file.*"
```

### Filtering by Level

To filter by minimum severity level (`debug`, `info`, `warning`, `error`, `critical`):

```bash
python .github/skills/vak-audit/audit.py --level warning
```

### Pagination

To fetch more logs or paginate through results:

```bash
python .github/skills/vak-audit/audit.py --limit 50 --offset 20
```

## Output

The script outputs a JSON array of audit entries. Each entry contains:
- `entry_id`: Unique identifier
- `timestamp`: Time of the event
- `agent_id`: The agent who performed the action
- `action`: The action name
- `resource`: The resource affected
- `level`: Severity level
- `policy_decision`: (Optional) Policy evaluation details (allow/deny)
- `details`: Additional context

## Example Output

```json
[
  {
    "entry_id": "audit-12345",
    "timestamp": "2023-10-27T10:00:00.000000",
    "level": "info",
    "agent_id": "agent-1",
    "action": "tool.execute",
    "resource": "calculator",
    "policy_decision": {
      "effect": "allow",
      "policy_id": "default-allow",
      "reason": "Allowed by default policy"
    },
    "details": {
      "tool_id": "calculator",
      "parameters": {"a": 1, "b": 2}
    }
  }
]
```
