#!/usr/bin/env python3
"""
VAK Management Skill Implementation

This script allows an agent to manage agents and tools in the Verifiable Agent Kernel (VAK).
It automatically attempts to install the VAK Python SDK if it is not found.
"""

import sys
import json
import argparse
import subprocess
from pathlib import Path

def install_vak_sdk():
    """Attempt to install the VAK SDK from the repository root."""
    try:
        # Determine repo root relative to this script
        # Script location: .github/skills/vak-manage/manage.py
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
    parser = argparse.ArgumentParser(description="Manage VAK agents and tools.")
    parser.add_argument("--list-agents", action="store_true", help="List all registered agents")
    parser.add_argument("--list-tools", action="store_true", help="List all available tools")
    parser.add_argument("--inspect-agent", help="Get details for a specific agent")
    parser.add_argument("--register-agent", help="ID of new agent to register")
    parser.add_argument("--agent-name", help="Name of new agent (optional, used with --register-agent)")
    parser.add_argument("--config", help="Path to kernel configuration file")

    args = parser.parse_args()

    # Initialize Kernel
    try:
        config_path = args.config
        if not config_path:
            # Look for vak_config.yaml in the same directory
            default_config = Path(__file__).parent / "vak_config.yaml"
            if default_config.exists():
                config_path = str(default_config)

        if config_path:
            kernel = VakKernel.from_config(config_path)
        else:
            kernel = VakKernel.default()
    except Exception as e:
        print(f"Error initializing kernel: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.list_agents:
            agents = kernel.list_agents()
            print(json.dumps(agents, indent=2))

        elif args.list_tools:
            tools = kernel.list_tools()
            print(json.dumps(tools, indent=2))

        elif args.inspect_agent:
            try:
                agent = kernel.get_agent(args.inspect_agent)
                print(json.dumps({
                    "agent_id": agent.agent_id,
                    "name": agent.name,
                    "description": agent.description,
                    "capabilities": agent.capabilities,
                    "allowed_tools": agent.allowed_tools,
                    "trusted": agent.trusted
                }, indent=2))
            except vak.AgentNotFoundError:
                print(f"Agent '{args.inspect_agent}' not found.", file=sys.stderr)
                sys.exit(1)

        elif args.register_agent:
            name = args.agent_name or f"Agent {args.register_agent}"
            config = AgentConfig(
                agent_id=args.register_agent,
                name=name,
                capabilities=["*"],
                allowed_tools=["*"],
                trusted=False
            )
            kernel.register_agent(config)
            print(f"Registered agent: {args.register_agent}")

        else:
            parser.print_help()

    except Exception as e:
        print(f"Error executing command: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        kernel.shutdown()

if __name__ == "__main__":
    main()
