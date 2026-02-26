package operation

import (
	"log/slog"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	pdppb "github.com/marcin/authz-pdp/pdp/gen/pdp"
	"google.golang.org/protobuf/types/known/structpb"
)

var logger = slog.Default()

// SetLogger replaces the package logger. Call once at startup before serving requests.
func SetLogger(l *slog.Logger) { logger = l }

const pdpFilterName = "pdp"

// Extract builds an Operation from the ext_authz CheckRequest route metadata.
// Never returns nil. All fields are "" when the route carries no pdp metadata.
func Extract(req *envoy_auth.CheckRequest) *pdppb.Operation {
	filterMeta := req.GetAttributes().GetMetadataContext().GetFilterMetadata()
	pdpMeta, ok := filterMeta[pdpFilterName]
	if !ok || pdpMeta == nil {
		logger.Debug("operation metadata absent")
	}
	return &pdppb.Operation{
		Id:      stringField(pdpMeta, "operation_id"),
		Scope:   stringField(pdpMeta, "scope"),
		Version: stringField(pdpMeta, "version"),
	}
}

// stringField extracts a string value from a structpb.Struct field.
// Returns "" if the struct is nil, the key is absent, or the value is not a string kind.
func stringField(s *structpb.Struct, key string) string {
	if s == nil {
		return ""
	}
	v, ok := s.Fields[key]
	if !ok || v == nil {
		return ""
	}
	return v.GetStringValue()
}
