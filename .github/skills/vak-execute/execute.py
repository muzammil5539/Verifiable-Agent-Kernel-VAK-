#!/usr/bin/env python3
"""
VAK Execute Skill Implementation

This script allows an agent to execute tools via the Verifiable Agent Kernel (VAK).
It enforces policies and generates audit logs for every execution.
"""

import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import Any, Dict

def install_vak_sdk():
    """Attempt to install the VAK SDK from the repository root."""
    try:
        # Determine repo root relative to this script
        # Script location: .github/skills/vak-execute/execute.py
        # Repo root: ../../../
        script_dir = Path(__file__).parent.resolve()
        repo_root = script_dir.parents[2]

        print(f"VAK SDK not found. Attempting to install from {repo_root}...", file=sys.stderr)
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-e", "."], cwd=repo_root)
        print("VAK SDK installed successfully.", file=sys.stderr)
    except Exception as e:
        print(f"Failed to install VAK SDK: {e}", file=sys.stderr)
        sys.exit(1)

try:
    import vak
except ImportError:
    install_vak_sdk()
    # Restart the script to pick up the new installation
    import os
    print("Restarting script to load installed VAK SDK...", file=sys.stderr)
    os.execl(sys.executable, sys.executable, *sys.argv)

from vak import VakKernel, AgentConfig

def main():
    parser = argparse.ArgumentParser(description="Execute a tool via VAK.")
    parser.add_argument("--agent-id", required=True, help="ID of the agent executing the tool")
    parser.add_argument("--tool-id", required=True, help="ID of the tool to execute")
    parser.add_argument("--action", required=True, help="Action/method to invoke on the tool")
    parser.add_argument("--params", help="JSON string of parameters")
    parser.add_argument("--params-file", help="Path to JSON file containing parameters")
    parser.add_argument("--timeout", type=int, default=5000, help="Timeout in milliseconds")
    parser.add_argument("--config", help="Path to kernel configuration file")
    parser.add_argument("--auto-register", action="store_true", help="Automatically register the agent if not found")

    args = parser.parse_args()

    # Parse parameters
    params: Dict[str, Any] = {}
    if args.params:
        try:
            params = json.loads(args.params)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON parameters: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.params_file:
        try:
            with open(args.params_file, "r") as f:
                params = json.load(f)
        except Exception as e:
            print(f"Error reading parameters file: {e}", file=sys.stderr)
            sys.exit(1)

    # Initialize Kernel
    try:
        config_path = args.config
        if not config_path:
            # Look for vak_config.yaml in the same directory
            default_config = Path(__file__).parent / "vak_config.yaml"
            if default_config.exists():
                config_path = str(default_config)

        if config_path:
            print(f"Loading kernel config from: {config_path}", file=sys.stderr)
            kernel = VakKernel.from_config(config_path)
        else:
            kernel = VakKernel.default()
    except Exception as e:
        print(f"Error initializing kernel: {e}", file=sys.stderr)
        sys.exit(1)

    # Check/Register Agent
    try:
        try:
            kernel.get_agent(args.agent_id)
        except vak.AgentNotFoundError:
            if args.auto_register:
                print(f"Agent '{args.agent_id}' not found. Auto-registering...", file=sys.stderr)
                config = AgentConfig(
                    agent_id=args.agent_id,
                    name=f"Auto-registered Agent {args.agent_id}",
                    description="Agent auto-registered by vak-execute skill",
                    capabilities=["*"],  # Give broad capabilities for testing
                    allowed_tools=["*"],  # Allow all tools for testing
                    trusted=False
                )
                kernel.register_agent(config)
            else:
                print(f"Agent '{args.agent_id}' not registered. Use --auto-register or register via vak-manage.", file=sys.stderr)
                sys.exit(1)
    except Exception as e:
        print(f"Error checking agent status: {e}", file=sys.stderr)
        sys.exit(1)

    # Execute Tool
    try:
        response = kernel.execute_tool(
            agent_id=args.agent_id,
            tool_id=args.tool_id,
            action=args.action,
            parameters=params,
            timeout_ms=args.timeout
        )

        # Output result as JSON
        output = {
            "success": response.success,
            "result": response.result,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms,
            "request_id": response.request_id
        }
        print(json.dumps(output, indent=2, default=str))

        if not response.success:
            sys.exit(1)

    except Exception as e:
        print(f"Error executing tool: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        kernel.shutdown()

if __name__ == "__main__":
    main()
