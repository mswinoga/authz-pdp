# Implementation Plan

## Overview

Go service implementing a gRPC ext_authz Policy Decision Point. The implementation
is structured as a set of focused packages assembled in `cmd/pdp/main.go`. Policy
is compiled once at startup; every request is a pure in-memory evaluation.

---

## Directory Layout

```
authz-pdp/
├── cmd/
│   └── pdp/
│       └── main.go                 gRPC server, flag parsing, Check() handler
├── pdp/
│   ├── proto/
│   │   └── model.proto             Actor, Subject, Operation proto definitions
│   ├── gen/
│   │   └── pdp/
│   │       └── model.pb.go         generated — do not edit
│   ├── model/
│   │   ├── actor/
│   │   │   ├── actor.go            certificate → *Actor (nil on absent/error)
│   │   │   └── actor_test.go
│   │   ├── subject/
│   │   │   ├── subject.go          filter metadata → *Subject (jwt nil if absent)
│   │   │   └── subject_test.go
│   │   └── operation/
│   │       ├── operation.go        route metadata → *Operation (empty strings if absent)
│   │       └── operation_test.go
│   ├── policy/
│   │   ├── policy.go               YAML parsing and schema validation
│   │   └── policy_test.go
│   └── cel/
│       ├── env.go                  CEL environment construction, proto registration
│       ├── evaluator.go            compile-once loader, per-request evaluation
│       └── evaluator_test.go
├── Makefile                        proto gen, build, test targets
├── buf.yaml                        buf configuration for proto generation
├── go.mod
└── policy.example.yaml
```

---

## Dependencies

go: version 1.23

```
github.com/google/cel-go                        v0.20+   CEL evaluation
github.com/envoyproxy/go-control-plane          latest   ext_authz CheckRequest/Response types
google.golang.org/grpc                          latest   gRPC server
google.golang.org/protobuf                      latest   proto runtime
gopkg.in/yaml.v3                                latest   YAML policy parsing
```

Standard library only for certificate parsing: `crypto/x509`, `encoding/pem`,
`net/url`, `regexp`.

---

## Phase 1 — Project Bootstrap

- `go mod init` with module path
- Create directory tree
- `buf.yaml` + `buf.gen.yaml` for protoc-gen-go code generation
- `Makefile` targets: `generate`, `build`, `test`, `lint`

---

## Phase 2 — Proto Definitions (`pdp/proto/model.proto`)

```proto
syntax = "proto3";
package pdp;
option go_package = "github.com/org/authz-pdp/pdp/gen/pdp";

import "google/protobuf/struct.proto";

message Actor {
  string cn   = 1;   // Subject CN;  "" if absent
  string dn   = 2;   // Subject DN (RFC 4514)
  string auid = 3;   // first Subject OU matching a[p0-9][0-9]{5}; "" if none
  string icn  = 4;   // Issuer CN
  string idn  = 5;   // Issuer DN
  string uri  = 6;   // URI SAN (e.g. SPIFFE ID); "" if absent
}

message Subject {
  google.protobuf.Struct jwt = 1;  // null when jwt_authn metadata absent
}

message Operation {
  string id      = 1;  // from operation_id key in filter_metadata.pdp; "" if absent
  string scope   = 2;
  string version = 3;
}
```

Run `make generate` after any proto change. Generated output goes to `pdp/gen/pdp/`.

---

## Phase 3 — Model Packages

### 3.1 `pdp/model/actor`

**Input:** `req.Attributes.Source.Certificate` — URL-encoded (percent-encoded) DER
certificate string set by Envoy from the TLS peer certificate.

**Output:** `*pdppb.Actor` or `nil`.

```
func Parse(certStr string) *pdppb.Actor
```

Steps:
1. Return `nil` if `certStr` is empty.
2. URL-decode: `url.PathUnescape(certStr)` → raw bytes string.
3. Parse DER: `x509.ParseCertificate([]byte(decoded))` → `*x509.Certificate`.
   Return `nil` on any error.
4. Build and return `*Actor`:
   - `cn`  — `cert.Subject.CommonName`
   - `dn`  — RFC 4514 string built from `cert.Subject` via `pkix.RDNSequence.String()`
   - `auid`— first element of `cert.Subject.OrganizationalUnit` matching `^a[p0-9][0-9]{5}$`; `""` if none
   - `icn` — `cert.Issuer.CommonName`
   - `idn` — RFC 4514 string from `cert.Issuer`
   - `uri` — `cert.URIs[0].String()` if `len(cert.URIs) > 0`; else `""`

Compile `auidPattern = regexp.MustCompile(...)` once at package init.

**Tests:** table-driven over PEM fixtures covering:
- empty input → nil
- valid cert with all fields populated
- valid cert with no URI SAN → uri `""`
- valid cert with no CN -> cn ""
- malformed input → nil
- cert with matching OU → auid populated
- cert with no matching OU → auid `""`

### 3.2 `pdp/model/subject`

**Input:** `req`, `-jwt-metadata-key` flag value.

**Output:** `*pdppb.Subject` (never nil; `Jwt` field is nil when metadata absent).

```
func Extract(req *envoy_auth.CheckRequest, jwtMetadataKey string) *pdppb.Subject
```

Steps:
1. Navigate: `req.Attributes.MetadataContext.FilterMetadata["envoy.filters.http.jwt_authn"]`
   → `*structpb.Struct`. Return `&Subject{Jwt: nil}` if absent.
2. Index by `jwtMetadataKey`: `struct.Fields[jwtMetadataKey]` → `*structpb.Value`.
   Return `&Subject{Jwt: nil}` if absent.
3. Call `.GetStructValue()` on the value → `*structpb.Struct`.
   Returns nil if the value is not of Struct kind.
4. Return `&Subject{Jwt: structValue}`.

**Tests:**
- nil filter metadata → `Subject{Jwt: nil}`
- jwt_authn key absent → `Subject{Jwt: nil}`
- configured key absent in jwt_authn metadata → `Subject{Jwt: nil}`
- value is not a Struct kind → `Subject{Jwt: nil}`
- valid JWT struct → `Subject{Jwt: <populated>}`

### 3.3 `pdp/model/operation`

**Input:** `req`.

**Output:** `*pdppb.Operation` (never nil; all fields `""` when metadata absent).

```
func Extract(req *envoy_auth.CheckRequest) *pdppb.Operation
```

Steps:
1. Navigate: `req.Attributes.MetadataContext.FilterMetadata["pdp"]` → `*structpb.Struct`.
2. Extract string values for keys `"operation_id"`, `"scope"`, `"version"` using
   `.Fields[key].GetStringValue()` — returns `""` for absent or non-string values.
3. Return `&Operation{Id: ..., Scope: ..., Version: ...}`.

**Tests:**
- nil pdp metadata → all fields `""`
- partial keys present
- all keys present → correct mapping
- non-string value for a key → `""`

---

## Phase 4 — Policy Package (`pdp/policy`)

### Schema

```go
type Policy struct {
    Version int    `yaml:"version"`
    Rules   []Rule `yaml:"rules"`
}

type Rule struct {
    ID    string `yaml:"id"`
    Allow string `yaml:"allow,omitempty"`
    Deny  string `yaml:"deny,omitempty"`
}
```

### Validation (enforced on load, fatal on failure)

- `version` must equal `1`
- `rules` must be non-empty
- Each rule: `id` non-empty, unique across all rules
- Each rule: exactly one of `allow` or `deny` present (not both, not neither)

```
func LoadFile(path string) (*Policy, error)
func Validate(p *Policy) error
```

**Tests:**
- valid policy → no error
- missing version → error
- wrong version → error
- rule with both allow and deny → error
- rule with neither → error
- duplicate rule IDs → error
- empty rules list → error

---

## Phase 5 — CEL Package (`pdp/cel`)

### 5.1 Environment (`env.go`)

Build the shared CEL environment once at startup. Register proto type descriptors
so field names are validated at compile time.

```
func buildEnv() (*cel.Env, error)
```

Variable declarations:

| Name | CEL type | Nullable |
|------|----------|----------|
| `actor` | `cel.ObjectType("pdp.Actor")` | yes — pass `types.NullValue` when nil |
| `subject` | `cel.ObjectType("pdp.Subject")` | no |
| `operation` | `cel.ObjectType("pdp.Operation")` | no |
| `resource` | `cel.StringType` | no |
| `action` | `cel.StringType` | no |

Proto type registration:
```go
cel.Types(
    new(pdppb.Actor),
    new(pdppb.Subject),
    new(pdppb.Operation),
)
```

**Null handling for `actor`:** the CEL env declares `actor` as the proto type.
In the activation, pass `types.NullValue` when the Go actor pointer is nil,
and the proto value otherwise. CEL's comparison `actor == null` evaluates
correctly against `types.NullValue`.

### 5.2 Evaluator (`evaluator.go`)

```go
type Evaluator struct {
    rules []compiledRule
}

type compiledRule struct {
    id       string
    decision string   // "allow" | "deny"
    program  cel.Program
}
```

**Startup — `NewEvaluator(policy *policy.Policy, env *cel.Env) (*Evaluator, error)`:**

For each rule in order:
1. Select expression: `rule.Allow` if non-empty, else `rule.Deny`.
2. `env.Compile(expr)` — returns AST + issues. Return error if issues are non-nil.
3. Assert output type is `bool`. Return error if not.
4. `env.Program(ast)` — store compiled program.

Any error here is fatal: service must not start with an invalid policy.

**Per-request — `Evaluate(ctx EvalContext) bool`:**

```go
type EvalContext struct {
    Actor     *pdppb.Actor    // nil if no cert
    Subject   *pdppb.Subject  // never nil; Subject.Jwt may be nil
    Operation *pdppb.Operation
    Resource  string
    Action    string
}
```

Build activation:
```go
actorVal := types.NullValue
if ctx.Actor != nil {
    actorVal = ctx.Actor
}
activation := map[string]any{
    "actor":     actorVal,
    "subject":   ctx.Subject,
    "operation": ctx.Operation,
    "resource":  ctx.Resource,
    "action":    ctx.Action,
}
```

Evaluation loop:
```
for each compiledRule:
    val, _, err := rule.program.Eval(activation)
    if err != nil:
        return false          // error → immediate deny
    b, ok := val.(ref.Val).Value().(bool)
    if !ok:
        return false          // non-bool → deny
    if b == true:
        return rule.decision == "allow"

return false                  // no match → deny
```

**Tests (`evaluator_test.go`):** table-driven, building full `Evaluator` from inline
policy YAML. Cover:

| Scenario                                                             | Expected               |
| -------------------------------------------------------------------- | ---------------------- |
| null actor, rule accesses `actor.cn` without guard                   | deny (CEL error)       |
| null actor, rule is `actor == null`                                  | match → apply decision |
| null `subject.jwt`, rule accesses `subject.jwt["sub"]` without guard | deny (CEL error)       |
| no rule matches                                                      | deny                   |
| first matching rule is allow                                         | allow                  |
| first matching rule is deny                                          | deny                   |
| rule error stops evaluation, later allow rule not reached            | deny                   |
| `has(actor.uri)` on populated uri                                    | true                   |
| `has(actor.uri)` on empty uri                                        | false                  |

---

## Phase 6 — gRPC Server (`cmd/pdp/main.go`)

### Startup flags

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `-policy-file` | string | yes | path to policy YAML |
| `-jwt-metadata-key` | string | yes | `payload_in_metadata` key configured in Envoy `jwt_authn` |
| `-port` | int | no | gRPC listen port (default: `9191`) |

### Startup sequence

1. Parse and validate flags.
2. `policy.LoadFile(policyFile)` — fatal on error.
3. `cel.BuildEnv()` — fatal on error.
4. `cel.NewEvaluator(policy, env)` — fatal on error (policy compilation).
5. Register gRPC server with `envoy_auth.RegisterAuthorizationServer`.
6. Listen and serve.

### `Check()` handler

```go
func (s *server) Check(
    ctx context.Context,
    req *envoy_auth.CheckRequest,
) (*envoy_auth.CheckResponse, error) {

    resource := req.GetAttributes().GetRequest().GetHttp().GetPath()
    action   := req.GetAttributes().GetRequest().GetHttp().GetMethod()
    subject  := subject.Extract(req, s.jwtMetadataKey)
    actor    := actor.Parse(req.GetAttributes().GetSource().GetCertificate())
    operation := operation.Extract(req)

    allow := s.evaluator.Evaluate(cel.EvalContext{
        Actor:     actor,
        Subject:   subject,
        Operation: operation,
        Resource:  resource,
        Action:    action,
    })

    if allow {
        return okResponse(), nil
    }
    return deniedResponse(), nil
}
```

`okResponse()` → `CheckResponse` with HTTP 200.
`deniedResponse()` → `CheckResponse` with HTTP 403.

No errors are returned from `Check()` — all error paths map to deny internally.

---

## Phase 7 — Testing Strategy

### Unit tests (per package, table-driven)

Covered in each phase above. Test files live alongside implementation files.

### Integration test (`cmd/pdp/main_test.go` or `pdp/cel/evaluator_test.go`)

End-to-end evaluation using a synthetic `CheckRequest` and a real policy.
Does not spin up a gRPC server — calls `Check()` logic directly.

Cover at minimum:
- Full allow path: valid cert + valid JWT + matching operation → 200
- Deny on null actor
- Deny on missing JWT
- Deny on no rule match
- Deny on CEL error

### Test fixtures

Place PEM certificate fixtures in `pdp/model/actor/testdata/`.
Place policy YAML fixtures in `pdp/policy/testdata/`.

---

## Implementation Order

Dependencies between phases:

```
Phase 1 (bootstrap)
    └── Phase 2 (proto)
            ├── Phase 3 (model packages)   ← independent of each other
            ├── Phase 4 (policy)           ← independent of model packages
            └── Phase 5 (cel)              ← depends on proto + policy
                    └── Phase 6 (server)   ← depends on all above
                            └── Phase 7 (integration tests)
```

Phases 3a/3b/3c (actor/subject/operation) and Phase 4 (policy) can be
developed in parallel after Phase 2 completes.

---

## Open Questions

1. **Module path** — confirm the Go module path (`github.com/org/authz-pdp` placeholder above).
2. **DN string format** — `pkix.RDNSequence.String()` produces a Go-specific format.
   If strict RFC 4514 is required, a third-party library (e.g. `github.com/go-ldap/ldap`)
   is needed. Document the chosen format so policy authors know what to match against.
3. **Multiple URI SANs** — current model exposes only `uri` (first URI SAN). If certs
   with multiple URI SANs are expected, this needs revisiting.
4. **gRPC server TLS** — the plan assumes plaintext gRPC between Envoy and PDP
   (standard for co-located sidecar deployments). If PDP runs out-of-cluster, TLS
   on the gRPC listener should be added.
5. **Certificate encoding** — Envoy documents `Source.Certificate` as URL-encoded DER.
   Verify against actual Envoy behaviour in the target environment; some versions
   produce URL-encoded PEM instead.
