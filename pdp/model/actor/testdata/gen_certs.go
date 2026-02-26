//go:build ignore

// Run once to regenerate PEM fixtures:
//   go run gen_certs_test.go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"time"
)

func mustKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func writePEM(name string, tmpl *x509.Certificate) {
	key := mustKey()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	f, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func main() {
	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)
	spiffeURI, _ := url.Parse("spiffe://prod/ns/foo/sa/svc-a")

	writePEM("full.pem", &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "svc-a",
			Organization:       []string{"Acme"},
			OrganizationalUnit: []string{"ap12345", "engineering"},
			Country:            []string{"US"},
		},
		URIs:      []*url.URL{spiffeURI},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	})

	writePEM("no_uri.pem", &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:         "svc-b",
			OrganizationalUnit: []string{"a012345"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	})

	writePEM("no_cn.pem", &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Acme"},
		},
		URIs:      []*url.URL{spiffeURI},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	})

	writePEM("no_auid.pem", &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject: pkix.Name{
			CommonName:         "svc-c",
			OrganizationalUnit: []string{"engineering", "platform"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	})
}
