# ADR-001: Operation ID as Primary Authorization Axis

**Status:** Accepted
**Date:** 2026-02-26

---

## Context

The PDP must evaluate authorization rules against an "operation" — what the client
is attempting to do. Two models were considered:

**Model A — Path/Verb rules**

Policy rules reference the raw HTTP request attributes directly:

```cel
action == "GET" && resource.startsWith("/api/v1/orders/")
```

**Model B — Semantic Operation ID**

Envoy route metadata carries a stable operation identifier sourced from the
OpenAPI `operationId`. Policy rules reference the identifier:

```cel
operation.id == "GetOrder"
```

---

## Decision

Use **semantic operation IDs** as the primary authorization axis.

`resource` and `action` (HTTP path and method) are retained in the CEL environment
as a fallback for routes without operation metadata (health checks, infrastructure
endpoints, simple cases).

---

## Rationale

### Path/verb rules couple policy to implementation

HTTP paths are implementation details. A path rename (`/v1/orders` → `/v2/orders`)
or restructuring forces a policy update even when the business operation and its
authorization semantics are unchanged. Policy should be coupled to *what the
operation means*, not *where it lives*.

### Cost structure favours operation IDs at scale

| | Operation ID | Path/Verb |
|--|--|--|
| Setup cost | one-time, per endpoint | none |
| Maintenance cost | near-zero | continuous (every path change) |
| Auditability | high (`"DeleteUser"` is unambiguous) | low (regex patterns) |
| API versioning | transparent | policy changes required |
| Coupling | business semantics | implementation detail |

For a PDP — a long-lived security component whose rules accumulate and are
audited — the continuous maintenance cost and poor auditability of path/verb
rules outweigh the zero setup cost.

### Auditability

`operation.id == "DeleteUser"` is unambiguous in a security audit.
`resource.matches("^/api/v[12]/users/[^/]+$") && action == "DELETE"` is not.

### API versioning is transparent

`v1` and `v2` paths can map to the same `operationId` in Envoy route metadata
when the operation is semantically unchanged, requiring no policy update.

---

## Consequences

### Envoy route metadata must be maintained

Each route that requires semantic authorization must carry a `filter_metadata`
block under the `pdp` key:

```yaml
metadata:
  filter_metadata:
    pdp:
      operation: "GetOrder"   # OpenAPI operationId
      scope: "orders"         # api name/id - grouping
      version: "v1"           # optional
```

This is a one-time cost per endpoint. If Envoy config is generated (from OpenAPI,
Helm, a control plane), operation ID population should be part of that generation.

### Naming convention must be established early

Operation ID naming must be agreed upon before policy rules are written.
Changing the scheme later forces policy rewrites. **Convention: use the OpenAPI
`operationId` verbatim.**

### Fallback to path/verb remains available

Routes without `operation` metadata (health checks, infrastructure routes) can
still be matched by `resource` and `action`. The two models are complementary:

```cel
# preferred — semantic rule
operation.id == "GetOrder"

# fallback — for routes without operation metadata
action == "GET" && resource == "/healthz"
```
