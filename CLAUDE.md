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

`req.Attributes.MetadataContext.FilterMetadata["envoy.filters.http.jwt_authn"]`

Initially we model subject with one attribute 'jwt':

`subject.jwt`

The JWT structure is preserved as structured data.



---

## 2.2 Actor

Actor identity is derived from downstream **mTLS client certificate**.

ext_authz config must include:

`include_peer_certificate: true`

PDP extracts:

req.Attributes.Source.Certificate

Identity extraction source based on parameter (`-identity-source`):
1. URI SAN
2. DNS SAN
3. subject DN

Actor is modelled as:

```go
actor {
  cn: string # certificate subject cn
  dn: string # certificate subject dn
  auid: string # the first certificate subject ou if it matches 'a[p0-9][0-9]{5}'
  icn: string # certificate issuer cn
  idn: string # certificate issuer dn
  uri: string # URI SAN - if present, otherwise nil
}
```

Actor is:
- `null` if no client certificate is provided or it fails to decode

Absence is never represented as `"anonymous"` or `""`.

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
        operation: "cart.item.list"
        scope: "billing"
        version: "v1"
```

operation is modelled as:

```go
operation {
  id: string
  scope: string
  version: string
}
```


---

# 3. Authorization Model


The PDP evaluates an ordered list of named CEL boolean expressions defined in a yaml policy:

Rules are evaluated in order until the first match (evaluation returns true). The first matched rule returns the rule key: allow or deny. If no rule matches, policy returns deny.

Policy structure:

```yaml
version: 1
default: deny
rules:
  - id: deny-no-actor
    deny: actor == null

  - id: allow-health
    allow: "admin" in subject.jwt.scopes()

  - id: allow-service-a-readonly
    allow: actor != null &&
           actor.cn == "svc-a" && actor.auid == "ap12345"
           operation.id in ["Order_Get", "Order_List"]

  - id: deny-all
    deny: true
```


## Implementation details that matter (performance + correctness)


### **Compile once**


At startup:
- parse YAML
- fast fail on invalid policy
- for each rule: env.Compile(rule.when) → cel.Program
- store compiled programs

Per request:
- build activation map (actor, subject, operation, …)
- iterate programs until match

Default posture:
- Fail closed
- Deny if policy evaluation fails
- Never allow on evaluation error

---

# 4. CEL Environment

Declared variables:

- `subject`
- `actor` (nullable)
- `operation`

---

# 5. Failure Semantics

System must fail closed.

## TLS layer

If mTLS required:
- Non-mTLS never reaches PDP.

If mTLS optional:
- Actor may be null.
- Policy must explicitly allow null actor.

## PDP layer

If:
- Certificate parse error
- CEL evaluation error

If:
- JWT metadata missing - it needs to be explicitly allowed

Never:
- Allow on error.
- Substitute fake identities.

---

# 6. Implementation Structure

```text
cmd/pdp/main.go        – gRPC server + wiring
pdp/model/actor/       – actor/certificate parsing
pdp/model/subject/     - subject/jwt parsing
pdp/model/operation/   - operation parsing
pdp/cel/               – CEL evaluator
```

Core flow inside `Check()` function implemented in main.go:
1. Construct input variables
2. Evaluate CEL
3. Return OkHttpResponse or DeniedHttpResponse

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

# 8. Non-Goals (Current MVP)

Not implemented:

- Policy bundles
- Policy hot reload
- Multiple named policies
- Delegation modeling (OBO)
- Metrics / tracing
- Audit logging

---

# 9. Future Directions

Likely next architectural extensions:

1. Delegation modeling (dedicated jwt claims)
2. Policy hot reload (SIGHUP/fsnotify/polling from central policy management server)
3. Metrics + decision logging

---

# 10. Design Principles

- Deterministic evaluation
- No network I/O in request path
- Minimal trusted input surface
- Clear separation of authentication vs authorization
- Deny by default
