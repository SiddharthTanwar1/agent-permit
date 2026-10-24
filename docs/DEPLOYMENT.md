# Integration and production checklist

1. Authenticate the user and agent in the host. Build `Context` from verified
   session claims; never accept principal or tenant from model arguments.
2. Load a reviewed policy at startup. Treat `PolicyError` as a startup failure.
   Give the model no write access to policy files, handler registry, or host code.
3. Register only narrow handlers. Use backend credentials with least privilege,
   parameterized queries, tenant-scoped connections, and restricted network egress.
4. Route every model-driven operation through `invoke`. Do not expose handlers
   independently, and do not use `evaluate` as an unenforced advisory check.
5. Provide a durable audit sink with access controls and retention limits. Raise
   on failure. Add trusted request IDs and outcome events in the host as needed;
   do not log raw inputs, outputs, or secrets by default.
6. Bound request size before JSON parsing, enforce rate/concurrency limits, and
   apply timeouts and idempotency at the application boundary. The synchronous
   guard does not interrupt a blocked handler. Async handlers are not supported.
7. Keep write, payment, deletion, and messaging tools out of autonomous policies
   until a host-side approval mechanism binds user consent to the exact operation.
8. Test your real adapters with tenant isolation and denied-call cases. Run CI,
   review dependency/action updates, and obtain independent security review for
   your deployment risk level.

## Operations

Policy changes: validate a new `Guard`, then atomically replace the application's
reference; existing requests may finish with the old snapshot. Record the policy
fingerprint alongside deployment version. Roll back by restoring a previously
reviewed policy. Do not hot-edit private instance fields.

Monitor allow/deny/invalid-input counts, audit failures, tool latency, and handler
exceptions. A spike in denials can indicate integration regressions or abuse; it
is not by itself proof of prompt injection. Never retry a side-effecting handler
without application-level idempotency.

The CLI is an offline diagnostic utility and has no listening socket. This release
ships as a Python library rather than an unauthenticated network gateway.
