#!/usr/bin/env python3
"""
VAK Policy Check Skill Implementation

This script allows an agent to check if an action is allowed by policy.
It automatically attempts to install the VAK Python SDK if it is not found.
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
        # Script location: .github/skills/vak-policy/check_policy.py
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

from vak import VakKernel, PolicyDecision, PolicyEffect

def main():
    parser = argparse.ArgumentParser(description="Check policy for an action.")
    parser.add_argument("--agent-id", required=True, help="ID of the agent")
    parser.add_argument("--action", required=True, help="Action to check")
    parser.add_argument("--resource", help="Resource to check against (default: *)")
    parser.add_argument("--context", help="JSON string of context attributes")
    parser.add_argument("--config", help="Path to kernel configuration file")

    args = parser.parse_args()

    # Parse context
    context: Dict[str, Any] = {}
    if args.resource:
        context["resource"] = args.resource
    else:
        context["resource"] = "*"

    if args.context:
        try:
            extra_context = json.loads(args.context)
            context.update(extra_context)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON context: {e}", file=sys.stderr)
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
            kernel = VakKernel.from_config(config_path)
        else:
            kernel = VakKernel.default()
    except Exception as e:
        print(f"Error initializing kernel: {e}", file=sys.stderr)
        sys.exit(1)

    # Evaluate Policy
    try:
        decision = kernel.evaluate_policy(
            agent_id=args.agent_id,
            action=args.action,
            context=context
        )

        # Output result as JSON
        output = {
            "allowed": decision.is_allowed(),
            "effect": decision.effect.value,
            "policy_id": decision.policy_id,
            "reason": decision.reason,
            "matched_rules": decision.matched_rules
        }
        print(json.dumps(output, indent=2, default=str))

        if decision.is_denied():
            sys.exit(1)

    except Exception as e:
        print(f"Error evaluating policy: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        kernel.shutdown()

if __name__ == "__main__":
    main()
