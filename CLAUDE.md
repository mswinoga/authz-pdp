# CLAUDE.md

## Project: PDP (Policy Decision Point)

This repository implements a standalone **Policy Decision Point (PDP)** consumed by **Envoy** via the `ext_authz` gRPC API.

The PDP:

- Receives authorization requests from Envoy
- Extracts:
  - **subject** from a verified unified JWT (provided by Envoy `jwt_authn`)
  - **actor** from downstream mTLS client certificate
- Evaluates a **CEL** policy expression
- Returns allow/deny decision to Envoy

This document describes architecture, invariants, and implementation rules.

---

# 1. Architecture Overview

## High-Level Flow

Client – Envoy (mTLS + JWT validation)  
-> ext_authz (gRPC) 
–> PDP (this service) 
–> CEL evaluation 
-> Allow / Deny  

## Responsibility Split

### Envoy responsibilities

- Enforce TLS
- Enforce mTLS (optional or required)
- Verify JWT signature & audience
- Extract JWT payload into dynamic metadata
- Forward client certificate (if configured)
- Call PDP via ext_authz
- Set `failure_mode_deny: true` on the ext_authz filter — requests must be denied when PDP is unreachable

### PDP responsibilities

- Extract identity context
- Construct authorization input model
- Evaluate CEL policy
- Return decision

The PDP **does not**:
- Validate JWT cryptographically
- Terminate TLS
- Trust client-provided headers

---

# 2.  Input Model


## 2.1 Subject

Derived from unified JWT validated by Envoy.

Envoy configuration:
- `jwt_authn`
- `payload_in_metadata`

PDP reads JWT claims from:

`req.Attributes.MetadataContext.FilterMetadata["envoy.filters.http.jwt_authn"][<key>]`

where `<key>` is configured via the `-jwt-metadata-key` startup flag. It must match
the `payload_in_metadata` value in the Envoy `jwt_authn` provider configuration.

Subject is modelled as:

```
subject {
  jwt: map(string, dyn) | null
}
```

`subject` is always non-null. `subject.jwt` is null when Envoy did not inject JWT
metadata (request arrived without a valid JWT, or `jwt_authn` is not configured
for the route).

When present, `subject.jwt` is converted from the protobuf Struct produced by
Envoy into a native `map(string, dyn)` before building the CEL activation.



---

## 2.2 Actor

Actor identity is derived from downstream **mTLS client certificate**.

ext_authz config must include:

`include_peer_certificate: true`

PDP extracts:

`req.Attributes.Source.Certificate`

Actor is modelled as:

```
actor {
  cn:   string  // certificate Subject CN; "" if absent
  dn:   string  // certificate Subject DN
  auid: string  // first Subject OU matching 'a[p0-9][0-9]{5}'; "" if none
  icn:  string  // issuer CN
  idn:  string  // issuer DN
  uri:  string  // URI SAN (e.g. SPIFFE ID); "" if absent
}
```

`actor` is null when no peer certificate is present or certificate parsing fails.
String fields are `""` (never null) when the attribute is absent from the certificate.

Absence is never represented as `"anonymous"`.

---

## 2.3 operation

operation id, scope, version are derived from route metadata configured in envoy and are optional:

```yaml
routes:
- match: { prefix: "/v1/cart/items" }
  route: { cluster: cart }
  metadata:
    filter_metadata:
      pdp:
        operation_id: "cart.item.list"
        scope: "billing"
        version: "v1"
```

operation is modelled as:

```
operation {
  id:      string  // maps from the `operation_id` key in filter_metadata.pdp
  scope:   string
  version: string
}
```

The `operation_id` key in route `filter_metadata.pdp` maps to `operation.id` in the
CEL environment. All fields are `""` when the route carries no `pdp` metadata.


---

# 3. Authorization Model


The PDP evaluates an ordered list of named CEL boolean expressions defined in a yaml policy.

Rules are evaluated in order until the first match (evaluation returns true). The first
matched rule returns its decision (allow or deny). **Default is always deny** — there is
no configurable default key; if no rule matches, the request is denied.

Policy schema:

- `version` — integer, schema version for forward compatibility (currently `1`)
- `rules` — ordered list of rules; each rule has exactly one of `allow` or `deny` (not both); a rule with both keys is a schema error and the service must fail at startup

Policy structure:

```yaml
version: 1
rules:
  - id: deny-no-identity
    deny: actor == null || !has(subject.jwt)

  - id: allow-admin
    allow: has(subject.jwt) && "order:admin" in subject.jwt["scopes"]

  - id: allow-order_get-readonly
    allow: actor != null && actor.cn == "svc-a" &&
           actor.auid == "ap12345" &&
           operation.id in ["Order_Get", "Order_List"]

  - id: deny-all
    deny: "true"
```


## Implementation details that matter (performance + correctness)


### **Compile once**


At startup:
- parse YAML
- fast fail on invalid policy
- for each rule: env.Compile(rule.allow/rule.deny) → cel.Program
- store compiled programs

Per request:
- build activation map (actor, subject, operation, resource, action)
- iterate rules in order until first match

Default posture:
- Fail closed
- Deny if no rule matches
- Never allow on evaluation error

### CEL Evaluation Semantics

Each rule expression produces one of three outcomes:

| Outcome | Meaning | Action |
|---------|---------|--------|
| `true` | rule matched | apply rule decision (allow/deny), stop |
| `false` | rule did not match | continue to next rule |
| error | runtime fault | **immediate deny, stop** |

Errors include: null field access without a null guard, type mismatch,
unknown function. An error in any rule causes the entire request to be denied
immediately — evaluation does not continue to the next rule.

**Null guard patterns:**

**Pattern 1 — Inline guard** (self-contained, rule-order-independent):

```cel
actor != null && actor.cn == "svc-a"
has(subject.jwt) && subject.jwt["sub"] == "user@example.com"
```

**Pattern 2 — Early-exit establishment** (a preceding deny rule guarantees
non-nullness for all subsequent rules):

```yaml
- id: deny-no-identity
  deny: actor == null || !has(subject.jwt)     # fires first; null never reaches below

- id: allow-svc-a                              # safe: null already denied above
  allow: actor.cn == "svc-a" && ...
```

Pattern 2 produces more readable rules but makes **rule order load-bearing**. If the
early-exit rule is removed or reordered, subsequent unguarded rules will error on null
input → deny. Prefer Pattern 1 for rules that may be reused or reordered. CEL
short-circuits `&&` and `||`, so guard must always precede field access.

---

# 4. CEL Environment

Declared variables and their types:

| Variable | Type | Nullable | Source |
|----------|------|----------|--------|
| `subject` | proto message | no | always present |
| `subject.jwt` | `google.protobuf.Struct` | yes | null when `jwt_authn` metadata absent |
| `actor` | proto message | yes | null when no peer cert or parse failure |
| `operation` | struct | no | fields are `""` when not configured in route metadata |
| `resource` | `string` | no | `req.Attributes.Request.Http.Path` |
| `action` | `string` | no | `req.Attributes.Request.Http.Method` (e.g. `"GET"`) |

## CEL Type Declaration Strategy

**`actor` — proto message**

`actor` is declared as a registered proto message in the CEL environment. This gives:

- Null handled natively: `actor == null` and `actor != null` work as expected
- Field names validated at compile time: `actor.cnn` (typo) fails at startup, not at request time
- Type mismatches caught at startup: `actor.cn > 5` fails before serving any traffic
- Rule syntax is **identical** to what would be written with `dyn` — no impact on policy authors

The `has()` macro is available for proto3 fields and checks for a non-zero value:

```cel
has(actor.uri)   # true iff actor.uri != "" — shorthand for "cert had a URI SAN"
```

**`subject` — proto message wrapper**

`subject` is a thin proto wrapper with a single `jwt` field. Being proto gives compile-time
validation that `subject.jwt` is the correct field name (typos like `subject.jwt_payload`
are caught at startup). Since `subject` is never null, this benefit is modest but consistent
with the actor approach.

**`subject.jwt` — `google.protobuf.Struct`**

JWT claims are dynamic — issuers vary and token schemas differ. A fixed proto message for
the JWT payload is not viable. `google.protobuf.Struct` is used, which CEL exposes with
identical map access syntax:

```cel
subject.jwt["sub"] == "alice"
"admin" in subject.jwt["roles"]
```

Claim names and value types cannot be validated at compile time. A typo like
`subject.jwt["subb"]` returns null at runtime (rule evaluates to false, not an error).

---

# 5. Failure Semantics

System must fail closed.

## TLS layer

If mTLS required:
- Non-mTLS never reaches PDP.

If mTLS optional:
- Actor may be null.
- Without an explicit allow rule for null actor, unauthenticated requests are denied by default.

## PDP layer

Absent identity is not an error — it is represented as null and passed to CEL:

- No peer certificate or parse failure → `actor = null`
- JWT metadata absent → `subject.jwt = null`

Policy is responsible for handling null explicitly. A rule that accesses a null
value without a guard produces a CEL evaluation error, which results in an
immediate deny.

The following result in immediate deny:

- CEL evaluation error (e.g. null field access without guard)
- CEL result is not a boolean
- Policy file invalid or fails to compile at startup (fast fail, service does not start)

Never:
- Allow on error.
- Substitute fake identities.

---

# 6. Implementation Structure

> Detailed implementation plan: [docs/implementation-plan.md](docs/implementation-plan.md)

```text
cmd/pdp/main.go        – gRPC server + wiring
pdp/model/actor/       – actor/certificate parsing
pdp/model/subject/     - subject/jwt parsing
pdp/model/operation/   - operation parsing
pdp/cel/               – CEL evaluator
├── internal/
│   └── logsetup/           named-logger level parsing and construction
```

Core flow inside `Check()` function implemented in main.go:

1. Extract `resource` from `req.Attributes.Request.Http.Path`
2. Extract `action` from `req.Attributes.Request.Http.Method`
3. Extract `subject.jwt` from `FilterMetadata["envoy.filters.http.jwt_authn"][<-jwt-metadata-key>]` → null if absent
4. Extract `actor` from `req.Attributes.Source.Certificate` → null if absent or parse failure
5. Extract `operation` fields from route `FilterMetadata["pdp"]` → empty strings if absent
6. Build CEL activation map
7. Evaluate rules in order; on first match apply decision and return
8. If no rule matches → deny
9. If any rule errors → deny immediately

---

# 7. Security Invariants

These must not be violated:
1. Actor identity must never be derived from headers.
2. JWT must never be re-validated in PDP
3. Absence of identity must not be encoded as a magic string.
4. Policy compilation must occur at startup only.
5. PDP must be stateless.
6. No external I/O (DB, HTTP) in request path.

---

# 8. Logging

## Named loggers

Each component writes to a named `log/slog` logger. Records include a `"logger"` key with the component name.

| Name | Component | Key events |
|------|-----------|------------|
| `server` | `cmd/pdp` | startup flags, listen address, per-request audit decision, shutdown |
| `cel` | `pdp/cel` | compiled N rules (INFO); per-rule result (DEBUG); CEL eval error (WARN) |
| `policy` | `pdp/policy` | policy loaded: path, version, rule count (INFO); validation error (ERROR) |
| `input` | `pdp/model/actor`, `pdp/model/subject`, `pdp/model/operation` | actor parse failure (WARN); jwt/operation metadata absent (DEBUG) |

## Log level flag

```
-log-level=<default>[,<logger>:<level>,...]
```

Examples:

```
-log-level=info                          # all loggers at INFO
-log-level=warn,cel:debug                # warn globally; CEL per-rule trace enabled
-log-level=info,cel:debug,policy:warn    # three-way override
```

Valid levels: `debug`, `info`, `warn`, `error` (case-insensitive).

## Audit log (per request, INFO)

One structured line per request logged by the `server` logger:

```json
{"logger":"server","msg":"decision","actor_cn":"svc-a","resource":"/v1/orders","action":"GET","rule":"allow-service-readonly","allow":true}
```

`actor_cn` is `""` when actor is null (no peer certificate). `rule` is `""` when no rule matched or a CEL error occurred.

## Security constraints

- JWT claim values are never logged.
- Certificate DER/PEM content is never logged.
- Only `actor.cn` is logged (not `auid`, not full DN).
- `resource` and `action` are HTTP transport metadata and are safe to log.

---

# 9. Architecture Decision Records

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-001](docs/adr/001-operation-id-vs-path-verb.md) | Operation ID as primary authorization axis | Accepted |

---

# 10. Non-Goals (Current MVP)

Not implemented:

- Policy bundles
- Policy hot reload
- Multiple named policies
- Delegation modeling (OBO)
- Metrics / tracing

---

# 11. Future Directions

Likely next architectural extensions:

1. Delegation modeling (dedicated jwt claims)
2. Policy hot reload (SIGHUP/fsnotify/polling from central policy management server)
3. Metrics + decision logging

---

# 12. Design Principles

- Deterministic evaluation
- No network I/O in request path
- Minimal trusted input surface
- Clear separation of authentication vs authorization
- Deny by default
