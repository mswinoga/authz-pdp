package subject

import (
	"log/slog"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	pdppb "github.com/marcin/authz-pdp/pdp/gen/pdp"
)

var logger = slog.Default()

// SetLogger replaces the package logger. Call once at startup before serving requests.
func SetLogger(l *slog.Logger) { logger = l }

const jwtAuthnFilterName = "envoy.filters.http.jwt_authn"

// Extract builds a Subject from the ext_authz CheckRequest.
// Never returns nil. Subject.Jwt is nil when jwt_authn metadata is absent,
// the configured key is missing, or the value is not a Struct.
func Extract(req *envoy_auth.CheckRequest, jwtMetadataKey string) *pdppb.Subject {
	filterMeta := req.GetAttributes().GetMetadataContext().GetFilterMetadata()
	if filterMeta == nil {
		return &pdppb.Subject{}
	}

	jwtAuthnMeta, ok := filterMeta[jwtAuthnFilterName]
	if !ok || jwtAuthnMeta == nil {
		return &pdppb.Subject{}
	}

	val, ok := jwtAuthnMeta.Fields[jwtMetadataKey]
	if !ok || val == nil {
		logger.Debug("jwt metadata absent", "key", jwtMetadataKey)
		return &pdppb.Subject{}
	}

	// GetStructValue returns nil if the Value is not of Struct kind.
	jwtStruct := val.GetStructValue()
	return &pdppb.Subject{Jwt: jwtStruct}
}
