---
name: vak-execute
description: Execute a tool through the Verifiable Agent Kernel (VAK). Use this when you need to run tools securely with policy enforcement and audit logging.
allowed-tools: python
---

# VAK Execute Skill

This skill allows you to execute tools via the Verifiable Agent Kernel (VAK). It ensures all actions are authorized by policy and logged for audit.

## Usage

Run the `execute.py` script to invoke tools. The script will automatically install the VAK SDK if it is missing.

### Basic Usage

To execute a tool:

```bash
python .github/skills/vak-execute/execute.py \
  --agent-id "my-agent" \
  --tool-id "calculator" \
  --action "add" \
  --params '{"a": 1, "b": 2}' \
  --auto-register
```

### Parameters

- `--agent-id`: The ID of the agent performing the action.
- `--tool-id`: The ID of the tool to execute.
- `--action`: The specific action/method to call on the tool.
- `--params`: JSON string of parameters.
- `--params-file`: Path to a JSON file containing parameters (useful for complex inputs).
- `--timeout`: Timeout in milliseconds (default: 5000).
- `--auto-register`: Automatically register the agent if it doesn't exist (useful for ad-hoc tasks).

### Example with Parameters File

Create a file `params.json`:
```json
{
  "data": [1, 2, 3, 4, 5],
  "operation": "mean"
}
```

Execute:
```bash
python .github/skills/vak-execute/execute.py \
  --agent-id "analyst-agent" \
  --tool-id "stats-tool" \
  --action "calculate" \
  --params-file params.json \
  --auto-register
```

## Output

The script outputs a JSON object with the execution result:

```json
{
  "success": true,
  "result": 3,
  "execution_time_ms": 12.5,
  "request_id": "req-12345"
}
```

If execution fails, the script will exit with a non-zero status code and print the error in the JSON output.
