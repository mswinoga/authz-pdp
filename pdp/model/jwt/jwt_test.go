package jwt

import (
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

const testKey = "jwt_payload"

func makeReq(filterMeta map[string]*structpb.Struct) *envoy_auth.CheckRequest {
	return &envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			MetadataContext: &core.Metadata{
				FilterMetadata: filterMeta,
			},
		},
	}
}

func TestExtract(t *testing.T) {
	validJWT, _ := structpb.NewStruct(map[string]any{
		"sub":   "alice",
		"roles": []any{"admin", "viewer"},
	})

	tests := []struct {
		name       string
		req        *envoy_auth.CheckRequest
		wantNil    bool
		wantSub    string
	}{
		{
			name:    "nil attributes",
			req:     &envoy_auth.CheckRequest{},
			wantNil: true,
		},
		{
			name:    "jwt_authn filter absent",
			req:     makeReq(map[string]*structpb.Struct{}),
			wantNil: true,
		},
		{
			name: "configured key absent in jwt_authn metadata",
			req: makeReq(map[string]*structpb.Struct{
				jwtAuthnFilterName: {Fields: map[string]*structpb.Value{
					"other_key": structpb.NewStringValue("x"),
				}},
			}),
			wantNil: true,
		},
		{
			name: "value is not a Struct kind (string value)",
			req: makeReq(map[string]*structpb.Struct{
				jwtAuthnFilterName: {Fields: map[string]*structpb.Value{
					testKey: structpb.NewStringValue("not-a-struct"),
				}},
			}),
			wantNil: true,
		},
		{
			name: "valid JWT struct",
			req: makeReq(map[string]*structpb.Struct{
				jwtAuthnFilterName: {Fields: map[string]*structpb.Value{
					testKey: structpb.NewStructValue(validJWT),
				}},
			}),
			wantNil: false,
			wantSub: "alice",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Extract(tc.req, testKey)
			if tc.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil *structpb.Struct")
			}
			sub := got.Fields["sub"].GetStringValue()
			if sub != tc.wantSub {
				t.Errorf("sub: want %q, got %q", tc.wantSub, sub)
			}
		})
	}
}
