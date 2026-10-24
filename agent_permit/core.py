"""Deterministic authorization for narrow AI agent tools. No model or network access."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable

MAX_BYTES = 65536
NAME = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")


class PolicyError(ValueError):
    """A policy or JSON document is invalid."""


class Denied(PermissionError):
    """The guard refused an invocation."""


def _pairs(pairs: list) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("duplicate JSON key")
        result[key] = value
    return result


def loads(text: str) -> Any:
    """Parse bounded, strict JSON; duplicate keys and non-finite numbers fail."""
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise PolicyError("document exceeds 64 KiB")
    try:
        return json.loads(text, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(PolicyError("non-finite number")))
    except (ValueError, RecursionError) as exc:
        raise PolicyError("invalid JSON") from exc


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise PolicyError("not JSON serializable") from exc


def _keys(value: Any, required: set, optional: set = frozenset()) -> None:
    if type(value) is not dict or not required <= value.keys() or value.keys() - required - optional:
        raise PolicyError("missing or unknown fields")


def _names(values: Any) -> None:
    if type(values) is not list or not values or any(type(v) is not str or not NAME.fullmatch(v) for v in values):
        raise PolicyError("expected nonempty list of identifiers")
    if len(set(values)) != len(values):
        raise PolicyError("duplicate identifiers")


@dataclass(frozen=True)
class Context:
    """Construct ONLY from authenticated host identity, never model arguments."""
    principal: str
    tenant: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str
    policy_digest: str

    def audit(self) -> dict:
        """Metadata only: deliberately excludes identity, arguments and results."""
        return {"schema_version": 1, "allowed": self.allowed,
                "code": self.code, "policy_digest": self.policy_digest}


class Guard:
    """Immutable policy snapshot and a synchronous, fail-closed execution boundary."""

    def __init__(self, policy: dict):
        encoded = _canonical(policy)
        self._policy = loads(encoded.decode())
        _keys(self._policy, {"version", "tools"})
        if type(self._policy["version"]) is not int or self._policy["version"] != 1:
            raise PolicyError("unsupported policy version")
        rules = self._policy["tools"]
        if type(rules) is not dict or not rules:
            raise PolicyError("tools must be a nonempty object")
        for name, rule in rules.items():
            if not NAME.fullmatch(name):
                raise PolicyError("invalid tool identifier")
            _keys(rule, {"principals", "tenants", "arguments"})
            _names(rule["principals"])
            _names(rule["tenants"])
            if type(rule["arguments"]) is not dict:
                raise PolicyError("arguments must be an object")
            for arg, spec in rule["arguments"].items():
                if not NAME.fullmatch(arg):
                    raise PolicyError("invalid argument identifier")
                _keys(spec, {"type"}, {"enum", "max_length", "minimum", "maximum"})
                kind = spec["type"]
                if kind not in ("string", "integer", "boolean"):
                    raise PolicyError("unsupported argument type")
                if kind == "string":
                    if "minimum" in spec or "maximum" in spec:
                        raise PolicyError("numeric bounds on string")
                    if type(spec.get("max_length")) is not int or not 1 <= spec["max_length"] <= 8192:
                        raise PolicyError("strings need max_length between 1 and 8192")
                elif "max_length" in spec:
                    raise PolicyError("max_length requires string")
                if kind == "integer":
                    if any(type(spec.get(k)) is not int for k in ("minimum", "maximum")):
                        raise PolicyError("integers need minimum and maximum")
                    if spec["minimum"] > spec["maximum"]:
                        raise PolicyError("reversed integer bounds")
                elif "minimum" in spec or "maximum" in spec:
                    raise PolicyError("bounds require integer")
                if "enum" in spec:
                    if type(spec["enum"]) is not list or not spec["enum"]:
                        raise PolicyError("enum must be nonempty")
                    if any(not self._valid(v, {k: v2 for k, v2 in spec.items() if k != "enum"}) for v in spec["enum"]):
                        raise PolicyError("enum values violate argument constraints")
        self.policy_digest = hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _valid(value: Any, spec: dict) -> bool:
        kind = spec["type"]
        if kind == "string":
            ok = type(value) is str and len(value) <= spec["max_length"]
        elif kind == "integer":
            ok = type(value) is int and spec["minimum"] <= value <= spec["maximum"]
        else:
            ok = type(value) is bool
        return ok and ("enum" not in spec or value in spec["enum"])

    def evaluate(self, tool: str, arguments: dict, context: Context) -> Decision:
        def result(code: str) -> Decision:
            return Decision(code == "allow", code, self.policy_digest)
        if type(tool) is not str or type(arguments) is not dict or type(context) is not Context:
            return result("invalid_request")
        if type(context.principal) is not str or type(context.tenant) is not str:
            return result("invalid_context")
        rule = self._policy["tools"].get(tool)
        if rule is None:
            return result("unknown_tool")
        if context.principal not in rule["principals"] or context.tenant not in rule["tenants"]:
            return result("identity_denied")
        if arguments.keys() != rule["arguments"].keys():
            return result("argument_shape_denied")
        if any(not self._valid(arguments[name], spec) for name, spec in rule["arguments"].items()):
            return result("argument_value_denied")
        return result("allow")

    def invoke(self, tool: str, arguments: dict, context: Context,
               handlers: dict[str, Callable], audit: Callable[[dict], None]) -> Any:
        """Snapshot args; authorize; persist decision; dispatch the exact checked args.

        Audit failure prevents execution. Handlers and audit sinks are trusted host code.
        Handler failures propagate and are never automatically retried.
        """
        snapshot = loads(_canonical(arguments).decode())
        decision = self.evaluate(tool, snapshot, context)
        if decision.allowed and tool not in handlers:
            decision = Decision(False, "handler_missing", self.policy_digest)
        audit(decision.audit())
        if not decision.allowed:
            raise Denied(decision.code)
        return handlers[tool](**snapshot)
