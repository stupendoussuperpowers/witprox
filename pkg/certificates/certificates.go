package certificates

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/stupendoussuperpowers/witprox/pkg/app"
)

var log = app.GetLogger("CERT")

func PersistCA(ca *tls.Certificate, caCertPath string, caKeyPath string) {
	certOut := new(bytes.Buffer)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate[0]})
	os.WriteFile(caCertPath, certOut.Bytes(), 0644)

	keyOut := new(bytes.Buffer)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ca.PrivateKey.(*rsa.PrivateKey))})

	os.WriteFile(caKeyPath, keyOut.Bytes(), 0600)
}

func LoadCA(caCertPath string, caKeyPath string) *tls.Certificate {
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

func InstallCA(caCertPath string) error {
	if runtime.GOOS != "linux" {
		return log.Errorf("Cert installation not supported for this platform")
	}

	targetPath := "/usr/local/share/ca-certificates/witprox.crt"

	src, err := os.Open(caCertPath)
	if err != nil {
		return log.Errorf("Cert not found: %v", err)
	}

	defer src.Close()

	dst, err := os.Create(targetPath)
	if err != nil {
		return log.Errorf("Create target cert: %v", err)
	}

	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return log.Errorf("Copy cert: %v", err)
	}

	cmd := exec.Command("update-ca-certificates")
	//cmd.Stdout = os.Stdout
	//cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return log.Errorf("update-ca-certificates failed: %v", err)
	}

	log.Info("Certificate installed")

	return nil
}

//
// The following util functions have been borrowed from: github.com/google/oss-rebuild project.
//

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
		log.Infof("failed to generate key: %v", err)
		return nil
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
