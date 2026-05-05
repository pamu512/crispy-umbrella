#!/usr/bin/env python3
"""Bacongris: dummy “workflow” for testing run_command + chat. No network; prints JSON to stdout, one line to stderr."""
import json
import os
import sys

def main() -> int:
    target = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.environ.get("BACONGRIS_TEST_EMAIL", "no-input@local.test")
    ).strip()
    out = {
        "kind": "bacongris_smoke_test",
        "input": target,
        "findings": [
            f"dummy row for {target!r}",
            "simulated: no real CTI data in this smoke run",
        ],
    }
    print(json.dumps(out, indent=2))
    print("INFO: stderr line (for log analysis test)", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
