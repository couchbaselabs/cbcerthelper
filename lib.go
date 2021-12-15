package cbcerthelper

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/pkg/sftp"
)

var (
	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
)

const (
	CertTypeCertificateRequest = "CERTIFICATE REQUEST"
	CertTypeCertificate        = "CERTIFICATE"
)

func EnableClientCertAuth(username, password, host string) error {
	bodyStr := `
{
  "state": "enable",
  "prefixes": [
    {
      "path": "san.email",
      "prefix": "",
      "delimiter": "@"
    }
  ]
}
`
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("http://%s:%s@%s:8091/settings/clientCertAuth", username, password, host),
		strings.NewReader(bodyStr),
	)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send request")
	}

	if resp.StatusCode == 200 || resp.StatusCode == 202 {
		return nil
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read response body for error")
	}

	return errors.Wrap(errors.New(string(b)), "server responded with error")
}

func ReloadClusterCert(username, password, host string) error {
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("http://%s:%s@%s:8091/node/controller/reloadCertificate", username, password, host),
		nil,
	)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send request")
	}

	if resp.StatusCode != 200 {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "failed to read response body for error")
		}

		return errors.Wrap(errors.New(string(b)), "server responded with error")
	}

	return nil
}

func UploadClusterCA(caBytes []byte, username, password, host string) error {
	var bCert bytes.Buffer
	bWriter := bufio.NewWriter(&bCert)

	if err := pem.Encode(bWriter, &pem.Block{Type: CertTypeCertificate, Bytes: caBytes}); err != nil {
		return errors.Wrap(err, "failed to encode certificate")
	}

	if err := bWriter.Flush(); err != nil {
		return errors.Wrap(err, "failed to create request payload")
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("http://%s:%s@%s:8091/controller/uploadClusterCA", username, password, host),
		bytes.NewReader(bCert.Bytes()),
	)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send request")
	}

	if resp.StatusCode != 200 {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "failed to read response body for error")
		}

		return errors.Wrap(errors.New(string(b)), "server responded with error")
	}

	return nil
}

func LoadTrustedCAs(username, password, host string) error {
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("http://%s:%s@%s:8091/node/controller/loadTrustedCAs", username, password, host),
		nil,
	)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send request")
	}

	if resp.StatusCode != 200 {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "failed to read response body for error")
		}

		return errors.Wrap(errors.New(string(b)), "server responded with error")
	}

	return nil
}

func createCertRequest(priv *rsa.PrivateKey, commonName string) (*x509.CertificateRequest, []byte, error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate request: %v", err)
	}

	return csr, csrBytes, nil
}

func CreateNodeCertReq(priv *rsa.PrivateKey) (*x509.CertificateRequest, []byte, error) {
	return createCertRequest(priv, "Couchbase Server")
}

func CreateNodeCert(notBefore, notAfter time.Time, caKey *rsa.PrivateKey, node string,
	ca *x509.Certificate, csr *x509.CertificateRequest) (*x509.Certificate, []byte, error) {

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,

		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,

		Issuer:  ca.Subject,
		Subject: csr.Subject,

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: false,
		IsCA:                  false,
		AuthorityKeyId:        []byte("keyid,issues:always"),
		SubjectKeyId:          []byte("hash"),
		IPAddresses:           []net.IP{net.ParseIP(node)},
	}

	nodeCertBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, csr.PublicKey, caKey)
	if err != nil {
		log.Fatalf("Failed to create node certificate: %v", err)
	}

	nodeCert, err := x509.ParseCertificate(nodeCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse node certificate: %v", err)
	}

	return nodeCert, nodeCertBytes, nil
}

func CreateRootCert(notBefore, notAfter time.Time, priv *rsa.PrivateKey) (*x509.Certificate, []byte, error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	rootTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Couchbase Root CA",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create root certificate: %v", err)
	}

	rootCert, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse root certificate: %v", err)
	}

	return rootCert, rootCertBytes, nil
}

func CreateIntCert(notBefore, notAfter time.Time, caKey *rsa.PrivateKey, ca *x509.Certificate,
	csr *x509.CertificateRequest, certEmail string) (*x509.Certificate, []byte, error) {

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,

		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,

		Issuer:  ca.Subject,
		Subject: csr.Subject,

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		// ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		// EmailAddresses:        []string{certEmail},
	}

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, csr.PublicKey, caKey)
	if err != nil {
		log.Fatalf("Failed to create node certificate: %v", err)
	}

	clientCert, err := x509.ParseCertificate(clientCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse node certificate: %v", err)
	}

	return clientCert, clientCertBytes, nil
}

func CreateClientCert(notBefore, notAfter time.Time, caKey *rsa.PrivateKey, ca *x509.Certificate,
	csr *x509.CertificateRequest, certEmail string) (*x509.Certificate, []byte, error) {

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,

		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,

		Issuer:  ca.Subject,
		Subject: csr.Subject,

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		EmailAddresses:        []string{certEmail},
	}

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, csr.PublicKey, caKey)
	if err != nil {
		log.Fatalf("Failed to create node certificate: %v", err)
	}

	clientCert, err := x509.ParseCertificate(clientCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse node certificate: %v", err)
	}

	return clientCert, clientCertBytes, nil
}

func CreateClientCertReq(username string, priv *rsa.PrivateKey) (*x509.CertificateRequest, []byte, error) {
	return createCertRequest(priv, username)
}

func WriteLocalCert(name, certType string, certBytes []byte) error {
	certOut, err := os.Create(name)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", name, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: certType, Bytes: certBytes}); err != nil {
		return fmt.Errorf("failed to write data to %s: %v", name, err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("error closing %s: %v", name, err)
	}
	return nil
}

func WriteLocalCerts(name, certType string, allCertBytes [][]byte) error {
	certOut, err := os.Create(name)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", name, err)
	}
	for _, certBytes := range allCertBytes {
		if err := pem.Encode(certOut, &pem.Block{Type: certType, Bytes: certBytes}); err != nil {
			return fmt.Errorf("failed to write data to %s: %v", name, err)
		}
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("error closing %s: %v", name, err)
	}
	return nil
}

func CreateCABundle(numRoots int, prefix string) error {
	name := prefix + ".pem"
	bundle, err := os.Create(name)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", name, err)
	}
	for i := 0; i < numRoots; i++ {
		name = fmt.Sprintf("%s_%d.pem", prefix, i)
		ca, err := ioutil.ReadFile(name)
		if err != nil {
			return fmt.Errorf("failed to read %s for writing: %v", name, err)
		}
		bundle.Write(ca)
	}
	return nil
}

func WriteLocalKey(name string, key *rsa.PrivateKey) error {
	keyOut, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", name, err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(key)

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write data to %s: %v", name, err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("error closing %s: %v", name, err)
	}
	return nil
}

func WriteRemoteCert(path, certType string, certBytes []byte, sftpCli *sftp.Client) error {
	f, err := sftpCli.Create(path)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: certType, Bytes: certBytes}); err != nil {
		return fmt.Errorf("failed to write data to %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("error closing %s: %v", path, err)
	}
	return nil
}

func WriteRemoteCerts(path, certType string, certBytess [][]byte, sftpCli *sftp.Client) error {
	f, err := sftpCli.Create(path)
	if err != nil {
		return err
	}
	for _, certBytes := range certBytess {
		if err := pem.Encode(f, &pem.Block{Bytes: certBytes, Type: certType}); err != nil {
			return fmt.Errorf("failed to write data to %s: %v", path, err)
		}
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("error closing %s: %v", path, err)
	}
	return nil
}

func WriteRemoteKey(path string, key *rsa.PrivateKey, sftpCli *sftp.Client) error {
	f, err := sftpCli.Create(path)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", path, err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(key)

	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write data to %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("error closing %s: %v", path, err)
	}
	return nil
}
