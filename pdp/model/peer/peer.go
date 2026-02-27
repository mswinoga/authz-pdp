package peer

import (
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	pdppb "github.com/marcin/authz-pdp/pdp/gen/pdp"
)

var logger = slog.Default()

// SetLogger replaces the package logger. Call once at startup before serving requests.
func SetLogger(l *slog.Logger) { logger = l }

var auidPattern = regexp.MustCompile(`^a[p0-9][0-9]{5}$`)

// Parse extracts a Peer from the peer certificate field of an ext_authz
// CheckRequest. The input is the URL-encoded DER or PEM certificate string
// set by Envoy in req.Attributes.Source.Certificate.
// Returns nil if the input is empty or cannot be parsed.
func Parse(certStr string) *pdppb.Peer {
	if certStr == "" {
		return nil
	}

	decoded, err := url.PathUnescape(certStr)
	if err != nil {
		logger.Warn("peer parse failed", "reason", "url unescape: "+err.Error())
		return nil
	}

	cert := parseCert([]byte(decoded))
	if cert == nil {
		logger.Warn("peer parse failed", "reason", "cert parse failed")
		return nil
	}

	return &pdppb.Peer{
		Cn:   cert.Subject.CommonName,
		Dn:   dnString(cert.Subject.ToRDNSequence()),
		Auid: extractAUID(cert.Subject.OrganizationalUnit),
		Icn:  cert.Issuer.CommonName,
		Idn:  dnString(cert.Issuer.ToRDNSequence()),
		Uri:  extractURISAN(cert),
	}
}

// parseCert attempts DER first, then PEM.
func parseCert(data []byte) *x509.Certificate {
	// Try DER directly.
	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert
	}
	// Fall back to PEM (some Envoy versions URL-encode PEM).
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

// dnString builds a comma-separated RFC 4514-style DN from an RDNSequence.
// Go's pkix.RDNSequence.String() returns the DN in reverse order per RFC 4514.
func dnString(rdns interface{ String() string }) string {
	s := rdns.String()
	// pkix.RDNSequence.String() may return "" for an empty name.
	return strings.TrimSpace(s)
}

func extractAUID(ous []string) string {
	for _, ou := range ous {
		if auidPattern.MatchString(ou) {
			return ou
		}
	}
	return ""
}

func extractURISAN(cert *x509.Certificate) string {
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	return ""
}
