# ADR-002: CEL Variable Naming and Null-Check Coherence

**Status:** Accepted
**Date:** 2026-02-26

---

## Context

Two related issues were identified with the initial CEL variable design.

### Issue 1 — `actor` is imprecise

The variable representing the mTLS peer certificate identity was named `actor`.
While borrowed from some authorization frameworks, it is generic and carries no
semantic information about how the identity was established. In this system the
identity comes from the mTLS peer certificate — the downstream service that
connected to Envoy.

Alternatives considered:

| Candidate  | Assessment                                                                                   |
| ---------- | -------------------------------------------------------------------------------------------- |
| `caller`   | Role-oriented ("who called us"); implies direction; correct but not grounded in any standard |
| `peer`     | Exact mTLS term ("peer certificate"); neutral; no role assumption; short                     |
| `workload` | SPIFFE/zero-trust aligned; unfamiliar outside that ecosystem                                 |
| `client`   | Heavily overloaded in HTTP/gRPC contexts                                                     |
| `source`   | Envoy's internal term (`req.Attributes.Source`); implies network topology, not identity      |

### Issue 2 — inconsistent null-check idioms

| Variable | Null check | Reason |
|----------|------------|--------|
| `actor` | `actor == null` | Top-level variable; `types.NullValue` passed in activation |
| `subject.jwt` | `!has(subject.jwt)` | Proto3 message *field*; CEL has no `== null` overload for map types |

Policy authors need two different idioms for what is conceptually the same check:
"is this identity present?" A natural attempt like `subject.jwt == null` fails at
compile time with an opaque type error.

Root cause: `actor` is a top-level CEL variable receiving `types.NullValue`, while
`subject.jwt` is a proto3 message field accessed through the `subject` wrapper.
CEL exposes `google.protobuf.Struct` fields as `map(string, dyn)`; maps have no
`== null` overload. The proto3 field-presence idiom (`has()`) is therefore required,
which is a different mental model from top-level variable nullability.

---

## Decision

### 1. Rename `actor` → `peer`

`peer` is the exact term used in mTLS ("peer certificate"). It is neutral, concise,
and carries no role assumption. Policy rules read naturally:

```cel
peer == null
peer.cn == "svc-a"
peer.uri == "spiffe://prod/ns/foo/sa/svc-a"
```

### 2. Promote `jwt` to a top-level nullable CEL variable

Remove `subject` from the CEL environment. Declare `jwt` as a top-level variable
of type `cel.DynType` — which is nullable in CEL.

- When JWT metadata is present: pass the decoded `*structpb.Struct`
- When JWT metadata is absent: pass `types.NullValue`

`jwt` is declared as `cel.DynType` rather than `cel.ObjectType("google.protobuf.Struct")`. Although `google.protobuf.Struct` is a CEL Well-Known Type, CEL's WKT adapter converts it to `map(string, dyn)` — and maps have no `== null` overload, so `jwt == null` would be a compile error. With `dyn`, both `jwt == null` and `jwt["sub"]` work as intended. The tradeoff is that CEL cannot validate at compile time that `jwt` is accessed as a map; however, since JWT claim names are dynamic by nature, this compile-time check was never available regardless.

### 3. JWT variable name: `jwt`

Alternatives considered:

| Candidate | Assessment |
|-----------|------------|
| `claims`  | Names the content; but "claim" collides conceptually with "a JWT claim" (an individual map entry), creating ambiguity |
| `token`   | Names the encoded wire artifact rather than the decoded payload |
| `principal` | Classical auth term; verbose in rules (`principal["sub"]`); no widespread CEL precedent |
| `user`    | Assumes JWT always represents a human identity — not always true (service tokens exist) |

`jwt` is the industry-standard shorthand, immediately recognizable on the stack.

---

## Result

Both identity variables share the same null-check idiom:

```cel
peer == null || jwt == null           # deny-no-identity (coherent)
peer != null && peer.cn == "svc-a"    # proto field access
jwt  != null && jwt["sub"] == "alice" # map/struct access
```

---

## Consequences

- **Policy syntax change**: `actor` → `peer`; `!has(subject.jwt)` / `has(subject.jwt)` → `jwt == null` / `jwt != null`. 
- **`Subject` proto**: remains in the Go internal model (`pdp/model/subject`) as an implementation detail of input extraction, but is no longer exposed as a CEL variable.
- **Rename scope**: CEL variable name, proto message (`Actor` → `Peer`), Go package (`pdp/model/actor` → `pdp/model/peer`).
- **Compile-time behaviour**: `jwt` is declared as `dyn` — no compile-time validation of access patterns. Claim names are dynamic by nature, so this is no regression from the previous `subject.jwt` model.
