# Threat model

## Boundary

Untrusted inputs are the model's tool name and argument object. Trusted inputs are
policy, authenticated identity, tool registry, handler code, and audit sink. The
host process and its dependencies are trusted. A model with arbitrary Python
execution or direct handler access can bypass this library.

## Threats and controls

| Threat | Control | Residual responsibility |
| --- | --- | --- |
| Invented privileged tool | Exact tool allowlist | Do not expose unguarded dispatch |
| Cross-tenant tool use | Principal and tenant checks | Authenticate identity; scope backend access |
| Extra permission flags | Reject unknown arguments | Never derive context from model output |
| Resource substitution | Enumerated logical IDs | Correctly map IDs in trusted adapters |
| Oversized / wrong-type args | Scalar types and bounds | Bound ingress bytes before parsing in a service |
| Audit outage | Persist-before-dispatch, fail closed | Sink must raise on persistence failure |
| Mutation between check and call | Copy JSON arguments before evaluation | Host must protect registry and policy objects |
| Ambiguous JSON | Reject duplicates and non-finite constants | Use strict parser at every ingress |

The guard is a permission check, not a natural-language trust classifier. It
allows any string satisfying policy constraints; a malicious instruction inside
that string remains untrusted data. A tool that interprets strings as shell,
SQL, template code, or further agent instructions needs additional controls.

## Audit semantics

Events prove only that the host attempted to record a decision. They do not prove
tool completion, provide cryptographic tamper evidence, or guarantee exactly-once
execution. Fingerprints identify policy snapshots; they are not signatures. Denied
calls through `invoke` are audited; malformed non-JSON inputs fail before a
decision event can be emitted. The host should count invalid requests separately
without logging their payloads. Exceptions from handlers propagate without retry.

## Deliberate exclusions

No authentication service, remote server, human approval workflow, distributed
quota accounting, policy signing, sandbox, output inspection, or durable audit
storage is included. Authorization revocation requires replacing the guard
instance. An in-flight call uses its existing snapshot. Review those lifecycle
semantics for the host application's threat model.
