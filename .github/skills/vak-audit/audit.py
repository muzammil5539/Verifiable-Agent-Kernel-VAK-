#!/usr/bin/env python3
"""
VAK Audit Skill Implementation

This script allows an agent to query the Verifiable Agent Kernel (VAK) audit logs.
It automatically attempts to install the VAK Python SDK if it is not found.
"""

import sys
import json
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

def install_vak_sdk():
    """Attempt to install the VAK SDK from the repository root."""
    try:
        # Determine repo root relative to this script
        # Script location: .github/skills/vak-audit/audit.py
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

from vak import VakKernel, AuditLevel

def main():
    parser = argparse.ArgumentParser(description="Query VAK audit logs.")
    parser.add_argument("--agent-id", help="Filter by Agent ID")
    parser.add_argument("--action", help="Filter by action (supports wildcards)")
    parser.add_argument("--level", help="Filter by minimum audit level (debug, info, warning, error, critical)")
    parser.add_argument("--limit", type=int, default=20, help="Maximum number of entries to return")
    parser.add_argument("--offset", type=int, default=0, help="Pagination offset")
    parser.add_argument("--config", help="Path to kernel configuration file")

    args = parser.parse_args()

    # Initialize Kernel
    try:
        if args.config:
            kernel = VakKernel.from_config(args.config)
        else:
            kernel = VakKernel.default()
    except Exception as e:
        print(f"Error initializing kernel: {e}", file=sys.stderr)
        sys.exit(1)

    # Convert level string to Enum
    level_enum = None
    if args.level:
        try:
            level_enum = AuditLevel(args.level.lower())
        except ValueError:
            print(f"Invalid audit level: {args.level}", file=sys.stderr)
            sys.exit(1)

    # Query Logs
    try:
        logs = kernel.get_audit_logs(
            agent_id=args.agent_id,
            action=args.action,
            level=level_enum,
            limit=args.limit,
            offset=args.offset
        )

        # Output as JSON
        result = [log.to_dict() for log in logs]
        print(json.dumps(result, indent=2, default=str))

    except Exception as e:
        print(f"Error querying audit logs: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        kernel.shutdown()

if __name__ == "__main__":
    main()
