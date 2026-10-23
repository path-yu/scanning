package mitm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	caCertFile = "ca.pem"
	caKeyFile  = "ca.key"
	leafTTL    = 397 * 24 * time.Hour
)

type Center struct {
	mu     sync.Mutex
	dir    string
	caCert *x509.Certificate
	caDER  []byte
	caPEM  []byte
	caKey  crypto.Signer
	leaves map[string]*tls.Certificate
}

type Status struct {
	Subject           string    `json:"subject"`
	SerialNumber      string    `json:"serialNumber"`
	FingerprintSHA256 string    `json:"fingerprintSha256"`
	ThumbprintSHA1    string    `json:"thumbprintSha1"`
	NotBefore         time.Time `json:"notBefore"`
	NotAfter          time.Time `json:"notAfter"`
	CAPath            string    `json:"caPath"`
	Platform          string    `json:"platform"`
	Installed         bool      `json:"installed"`
	InstallTargets    []string  `json:"installTargets"`
	ManualCommands    []string  `json:"manualCommands"`
}

func LoadOrCreate(dir string) (*Center, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建证书目录 %s: %w", dir, err)
	}

	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	if certExists && keyExists {
		return loadCenter(dir, certPath, keyPath)
	}
	if certExists != keyExists {
		return nil, fmt.Errorf("证书目录不完整：%s 与 %s 必须同时存在；如需重新生成，请同时删除两者", certPath, keyPath)
	}

	c := &Center{dir: dir, leaves: make(map[string]*tls.Certificate)}
	if err := c.generateLocked(); err != nil {
		return nil, err
	}
	return c, nil
}

func loadCenter(dir, certPath, keyPath string) (*Center, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("读取根证书: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("读取根私钥: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("ca.pem 不是有效的证书 PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析根证书: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("ca.pem 不是 CA 证书")
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, errors.New("ca.pem 与 ca.key 不匹配")
	}

	return &Center{
		dir:    dir,
		caCert: cert,
		caDER:  append([]byte(nil), certBlock.Bytes...),
		caPEM:  append([]byte(nil), certPEM...),
		caKey:  key,
		leaves: make(map[string]*tls.Certificate),
	}, nil
}

func (c *Center) generateLocked() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成根私钥: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	subjectKeyID, err := keyID(&key.PublicKey)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Scanning Root CA",
			Organization: []string{"Scanning"},
			Country:      []string{"CN"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		SubjectKeyId:          subjectKeyID,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("签发根证书: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("解析新根证书: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("编码根私钥: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(c.dir, caCertFile), certPEM, 0o644); err != nil {
		return fmt.Errorf("写入根证书: %w", err)
	}
	if err := os.WriteFile(filepath.Join(c.dir, caKeyFile), keyPEM, 0o600); err != nil {
		return fmt.Errorf("写入根私钥: %w", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(filepath.Join(c.dir, caKeyFile), 0o600)
	}

	c.caCert = cert
	c.caDER = append([]byte(nil), der...)
	c.caPEM = append([]byte(nil), certPEM...)
	c.caKey = key
	c.leaves = make(map[string]*tls.Certificate)
	return nil
}

func (c *Center) CertificateFor(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return nil, errors.New("证书目标主机为空")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if cert, ok := c.leaves[host]; ok {
		return cert, nil
	}
	cert, err := c.issueLocked(host)
	if err != nil {
		return nil, err
	}
	if len(c.leaves) >= 4096 {
		c.leaves = make(map[string]*tls.Certificate)
	}
	c.leaves[host] = cert
	return cert, nil
}

func (c *Center) issueLocked(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成叶证书私钥: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	subjectKeyID, err := keyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	cn := host
	if len(cn) > 64 {
		cn = cn[:64]
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: cn, Organization: []string{"Scanning"}},
		NotBefore:      now.Add(-time.Hour),
		NotAfter:       now.Add(leafTTL),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:   subjectKeyID,
		AuthorityKeyId: c.caCert.SubjectKeyId,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.caCert, &key.PublicKey, c.caKey)
	if err != nil {
		return nil, fmt.Errorf("签发 %s 的证书: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("解析 %s 的证书: %w", host, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.caDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func (c *Center) Rotate() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generateLocked()
}

func (c *Center) CAPEM() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.caPEM...)
}

func (c *Center) CAPath() string {
	return filepath.Join(c.dir, caCertFile)
}

func (c *Center) Status() Status {
	c.mu.Lock()
	cert := c.caCert
	caPath := filepath.Join(c.dir, caCertFile)
	thumb := thumbprintSHA1(c.caDER)
	c.mu.Unlock()

	status := Status{
		Subject:           cert.Subject.String(),
		SerialNumber:      cert.SerialNumber.String(),
		FingerprintSHA256: fingerprintSHA256(cert.Raw),
		ThumbprintSHA1:    thumb,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		CAPath:            caPath,
		Platform:          runtime.GOOS,
		InstallTargets:    []string{"user", "system"},
	}
	status.Installed = isInstalled(cert, caPath, thumb)
	status.ManualCommands = manualCommands(caPath)
	return status
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("生成证书序列号: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func keyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("编码公钥: %w", err)
	}
	sum := sha1.Sum(der)
	return sum[:], nil
}

func parsePrivateKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("根私钥不是有效的 PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, errors.New("根私钥类型不支持")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("无法解析根私钥")
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	da, errA := x509.MarshalPKIXPublicKey(a)
	db, errB := x509.MarshalPKIXPublicKey(b)
	return errA == nil && errB == nil && bytes.Equal(da, db)
}

func fingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return formatHexColon(sum[:])
}

func thumbprintSHA1(der []byte) string {
	sum := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func formatHexColon(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(parts, ":")
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
