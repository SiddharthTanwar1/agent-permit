"""Offline policy evaluator. Never executes tools."""
import argparse
import json
import sys
from pathlib import Path

from .core import MAX_BYTES, Context, Guard, PolicyError, loads


def read(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise PolicyError("document too large")
    return loads(raw.decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Evaluate an AI tool call without executing it")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    try:
        guard = Guard(read(args.policy))
        request = read(args.request)
        if type(request) is not dict or request.keys() != {"tool", "arguments"}:
            raise PolicyError("invalid request envelope")
        decision = guard.evaluate(request["tool"], request["arguments"], Context(args.principal, args.tenant))
        print(json.dumps(decision.audit(), sort_keys=True))
        return 0 if decision.allowed else 2
    except (OSError, UnicodeError, PolicyError):
        print('{"error":"invalid_input"}', file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
