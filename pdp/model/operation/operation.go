package operation

import (
	"log/slog"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	pdppb "github.com/marcin/authz-pdp/pdp/gen/pdp"
	"google.golang.org/protobuf/types/known/structpb"
)

const pdpFilterName = "pdp"

// Extract builds an Operation from the ext_authz CheckRequest route metadata.
// Never returns nil. All fields are "" when the route carries no pdp metadata.
// Route metadata is read from route_metadata_context, which requires
// route_metadata_context_namespaces: [pdp] in the ext_authz filter config.
func Extract(req *envoy_auth.CheckRequest, log *slog.Logger) *pdppb.Operation {
	routeMeta := req.GetAttributes().GetRouteMetadataContext().GetFilterMetadata()
	pdpMeta, ok := routeMeta[pdpFilterName]
	if !ok || pdpMeta == nil {
		log.Debug("operation metadata absent — check route_metadata_context_namespaces in ext_authz config",
			"namespace", pdpFilterName)
	}
	op := &pdppb.Operation{
		Id:      stringField(pdpMeta, "operation_id"),
		Api:     stringField(pdpMeta, "api"),
		Version: stringField(pdpMeta, "version"),
	}
	log.Debug("operation extracted", "id", op.Id, "api", op.Api, "version", op.Version)
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
