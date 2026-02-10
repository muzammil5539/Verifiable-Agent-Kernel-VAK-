---
name: vak-manage
description: Manage agents and tools in the Verifiable Agent Kernel (VAK). Use this to register agents, list capabilities, or inspect registered tools.
allowed-tools: python
---

# VAK Management Skill

This skill allows you to manage agents and inspect tools within the Verifiable Agent Kernel (VAK). You can list registered agents, inspect their configuration, or register new agents for testing purposes.

## Usage

Run the `manage.py` script. The script will automatically install the VAK SDK if it is missing.

### List Agents

To see all registered agents:

```bash
python .github/skills/vak-manage/manage.py --list-agents
```

### List Tools

To see all available tools:

```bash
python .github/skills/vak-manage/manage.py --list-tools
```

### Inspect Agent

To get detailed configuration for a specific agent:

```bash
python .github/skills/vak-manage/manage.py --inspect-agent "agent-123"
```

### Register Agent

To register a new agent (useful before executing tools with `vak-execute`):

```bash
python .github/skills/vak-manage/manage.py --register-agent "new-agent" --agent-name "My New Agent"
```

## Output

The script outputs JSON-formatted lists or objects depending on the command.

Example output for `--inspect-agent`:

```json
{
  "agent_id": "agent-123",
  "name": "Test Agent",
  "description": "A test agent",
  "capabilities": ["*"],
  "allowed_tools": ["calculator"],
  "trusted": false
}
```
