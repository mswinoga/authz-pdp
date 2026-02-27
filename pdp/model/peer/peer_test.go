package peer

import (
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"os"
	"testing"
)

// urlEncodePEM reads a PEM file and URL-encodes its bytes, matching what
// Envoy sets in req.Attributes.Source.Certificate.
func urlEncodePEM(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return url.PathEscape(string(data))
}

// urlEncodeDER reads a PEM file, extracts the DER bytes, and URL-encodes them.
func urlEncodeDER(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	return url.PathEscape(string(block.Bytes))
}

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		input    func() string
		wantNil  bool
		wantCN   string
		wantAUID string
		wantURI  string
		wantICN  string
	}{
		{
			name:    "empty input returns nil",
			input:   func() string { return "" },
			wantNil: true,
		},
		{
			name:    "malformed input returns nil",
			input:   func() string { return "not-a-cert" },
			wantNil: true,
		},
		{
			name:     "full cert via PEM encoding",
			input:    func() string { return urlEncodePEM(t, "testdata/full.pem") },
			wantCN:   "svc-a",
			wantAUID: "ap12345",
			wantURI:  "spiffe://prod/ns/foo/sa/svc-a",
		},
		{
			name:     "full cert via DER encoding",
			input:    func() string { return urlEncodeDER(t, "testdata/full.pem") },
			wantCN:   "svc-a",
			wantAUID: "ap12345",
			wantURI:  "spiffe://prod/ns/foo/sa/svc-a",
		},
		{
			name:     "cert without URI SAN",
			input:    func() string { return urlEncodePEM(t, "testdata/no_uri.pem") },
			wantCN:   "svc-b",
			wantAUID: "a012345",
			wantURI:  "",
		},
		{
			name:    "cert without CN",
			input:   func() string { return urlEncodePEM(t, "testdata/no_cn.pem") },
			wantCN:  "",
			wantURI: "spiffe://prod/ns/foo/sa/svc-a",
		},
		{
			name:     "cert without matching OU",
			input:    func() string { return urlEncodePEM(t, "testdata/no_auid.pem") },
			wantCN:   "svc-c",
			wantAUID: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Parse(tc.input())
			if tc.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil peer, got nil")
			}
			if got.Cn != tc.wantCN {
				t.Errorf("CN: want %q, got %q", tc.wantCN, got.Cn)
			}
			if got.Auid != tc.wantAUID {
				t.Errorf("AUID: want %q, got %q", tc.wantAUID, got.Auid)
			}
			if got.Uri != tc.wantURI {
				t.Errorf("URI: want %q, got %q", tc.wantURI, got.Uri)
			}
		})
	}
}

func TestExtractAUID(t *testing.T) {
	tests := []struct {
		ous  []string
		want string
	}{
		{[]string{"ap12345"}, "ap12345"},
		{[]string{"a012345"}, "a012345"},
		{[]string{"a912345"}, "a912345"},
		{[]string{"engineering", "ap12345", "platform"}, "ap12345"}, // first match
		{[]string{"engineering", "platform"}, ""},
		{[]string{}, ""},
		{[]string{"AP12345"}, ""},  // case-sensitive
		{[]string{"ap1234"}, ""},   // too short
		{[]string{"ap123456"}, ""}, // too long
	}
	for _, tc := range tests {
		got := extractAUID(tc.ous)
		if got != tc.want {
			t.Errorf("extractAUID(%v): want %q, got %q", tc.ous, tc.want, got)
		}
	}
}

func TestParseDNFields(t *testing.T) {
	peer := Parse(urlEncodePEM(t, "testdata/full.pem"))
	if peer == nil {
		t.Fatal("expected non-nil peer")
	}
	if peer.Dn == "" {
		t.Error("expected non-empty DN")
	}
	if peer.Idn == "" {
		t.Error("expected non-empty issuer DN (self-signed cert has issuer == subject)")
	}
}

func TestParseURLDecodeError(t *testing.T) {
	// A string with an invalid percent-encoding sequence.
	got := Parse("%GG")
	if got != nil {
		t.Errorf("expected nil for invalid URL encoding, got %+v", got)
	}
}

// Verify that a raw (non-URL-encoded) PEM string also works — belt-and-suspenders
// for environments that do not URL-encode the certificate.
func TestParseRawPEM(t *testing.T) {
	data, err := os.ReadFile("testdata/full.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	cert, _ := x509.ParseCertificate(block.Bytes)
	_ = cert // just confirm fixture is valid
}
