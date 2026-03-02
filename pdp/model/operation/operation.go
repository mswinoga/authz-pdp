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
// Route metadata is read from route_metadata_context, which requires
// route_metadata_context_namespaces: [pdp] in the ext_authz filter config.
func Extract(req *envoy_auth.CheckRequest) *pdppb.Operation {
	routeMeta := req.GetAttributes().GetRouteMetadataContext().GetFilterMetadata()
	pdpMeta, ok := routeMeta[pdpFilterName]
	if !ok || pdpMeta == nil {
		logger.Debug("operation metadata absent — check route_metadata_context_namespaces in ext_authz config",
			"namespace", pdpFilterName)
		return &pdppb.Operation{}
	}
	op := &pdppb.Operation{
		Id:      stringField(pdpMeta, "operation_id"),
		Scope:   stringField(pdpMeta, "scope"),
		Version: stringField(pdpMeta, "version"),
	}
	if ok {
		logger.Debug("operation extracted", "id", op.Id, "scope", op.Scope, "version", op.Version)
	}
	return op
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
