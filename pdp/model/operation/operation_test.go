package operation

import (
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

func makeReq(pdpFields map[string]any) *envoy_auth.CheckRequest {
	var filterMeta map[string]*structpb.Struct
	if pdpFields != nil {
		s, err := structpb.NewStruct(pdpFields)
		if err != nil {
			panic(err)
		}
		filterMeta = map[string]*structpb.Struct{pdpFilterName: s}
	}
	return &envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			RouteMetadataContext: &core.Metadata{
				FilterMetadata: filterMeta,
			},
		},
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name          string
		req           *envoy_auth.CheckRequest
		wantID        string
		wantScope     string
		wantVersion   string
	}{
		{
			name:        "nil attributes",
			req:         &envoy_auth.CheckRequest{},
			wantID:      "",
			wantScope:   "",
			wantVersion: "",
		},
		{
			name:        "no pdp metadata",
			req:         makeReq(nil),
			wantID:      "",
			wantScope:   "",
			wantVersion: "",
		},
		{
			name:        "all fields present",
			req:         makeReq(map[string]any{"operation_id": "GetOrder", "scope": "orders", "version": "v1"}),
			wantID:      "GetOrder",
			wantScope:   "orders",
			wantVersion: "v1",
		},
		{
			name:        "partial fields",
			req:         makeReq(map[string]any{"operation_id": "ListOrders"}),
			wantID:      "ListOrders",
			wantScope:   "",
			wantVersion: "",
		},
		{
			name:        "non-string value for key",
			req:         makeReq(map[string]any{"operation_id": 42.0}),
			wantID:      "",
			wantScope:   "",
			wantVersion: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Extract(tc.req)
			if got == nil {
				t.Fatal("Extract must never return nil")
			}
			if got.Id != tc.wantID {
				t.Errorf("ID: want %q, got %q", tc.wantID, got.Id)
			}
			if got.Scope != tc.wantScope {
				t.Errorf("Scope: want %q, got %q", tc.wantScope, got.Scope)
			}
			if got.Version != tc.wantVersion {
				t.Errorf("Version: want %q, got %q", tc.wantVersion, got.Version)
			}
		})
	}
}
