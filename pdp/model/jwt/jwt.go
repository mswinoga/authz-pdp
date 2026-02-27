package jwt

import (
	"log/slog"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

var logger = slog.Default()

// SetLogger replaces the package logger. Call once at startup before serving requests.
func SetLogger(l *slog.Logger) { logger = l }

const jwtAuthnFilterName = "envoy.filters.http.jwt_authn"

// Extract returns the JWT claims struct from the ext_authz CheckRequest, or nil
// when jwt_authn metadata is absent, the configured key is missing, or the value
// is not a Struct.
func Extract(req *envoy_auth.CheckRequest, jwtMetadataKey string) *structpb.Struct {
	filterMeta := req.GetAttributes().GetMetadataContext().GetFilterMetadata()
	if filterMeta == nil {
		logger.Debug("filter_metadata absent — check metadata_context_namespaces in ext_authz config")
		return nil
	}

	jwtAuthnMeta, ok := filterMeta[jwtAuthnFilterName]
	if !ok || jwtAuthnMeta == nil {
		logger.Debug("jwt_authn namespace absent from filter_metadata — check metadata_context_namespaces in ext_authz config",
			"namespace", jwtAuthnFilterName)
		return nil
	}

	val, ok := jwtAuthnMeta.Fields[jwtMetadataKey]
	if !ok || val == nil {
		logger.Debug("jwt payload key absent — check payload_in_metadata in jwt_authn provider config matches -jwt-metadata-key flag",
			"key", jwtMetadataKey)
		return nil
	}

	// GetStructValue returns nil if the Value is not of Struct kind.
	s := val.GetStructValue()
	if s == nil {
		logger.Debug("jwt metadata value is not a Struct", "key", jwtMetadataKey)
		return nil
	}

	logger.Debug("jwt extracted", "claims", len(s.Fields))
	return s
}
