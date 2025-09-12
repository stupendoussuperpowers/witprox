package certificates

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

var (
	caCertPath = "/tmp/ca.pem"
	caKeyPath  = "/tmp/ca-key.pem"
)

func PersistCA(ca *tls.Certificate) {
	certOut := new(bytes.Buffer)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate[0]})
	os.WriteFile(caCertPath, certOut.Bytes(), 0644)

	keyOut := new(bytes.Buffer)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ca.PrivateKey.(*rsa.PrivateKey))})

	os.WriteFile(caKeyPath, keyOut.Bytes(), 0600)
}

func LoadCA() *tls.Certificate {
	if _, err := os.Stat(caCertPath); err != nil {
		return nil
	}

	certPEM, _ := os.ReadFile(caCertPath)
	keyPEM, _ := os.ReadFile(caKeyPath)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("failed to load persisted ca: %v", err)
	}

	caLeaf, _ := x509.ParseCertificate(cert.Certificate[0])
	cert.Leaf = caLeaf
	return &cert
}

// GenerateCA generates a ca certificate.
func GenerateCA() *tls.Certificate {
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2394),
		Subject: pkix.Name{
			CommonName: "Proxy Witprox",
			Locality:   []string{"New York City"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	// TODO: Switch to ed25519.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("failed to create CA: %v", err)
	}
	ca := new(tls.Certificate)
	ca.Certificate = append(ca.Certificate, caBytes)
	ca.PrivateKey = priv
	if ca.Leaf, err = x509.ParseCertificate(caBytes); err != nil {
		log.Fatalf("failed to parse CA leaf: %v", err)
	}
	return ca
}

// ToPEM encodes a certificate to PEM format.
func ToPEM(cert *x509.Certificate) []byte {
	b := new(bytes.Buffer)
	pem.Encode(b, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return b.Bytes()
}
