package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/mailedge/internal/config"
)

// Info describes a stored certificate.
type Info struct {
	Name       string    `json:"name"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	Source     string    `json:"source,omitempty"`
	CertPath   string    `json:"cert_path"`
	KeyPath    string    `json:"key_path"`
	DaysLeft   int       `json:"days_left"`
}

// Manager loads certificates, CA pool and optional ACME.
type Manager struct {
	cfg *config.Config
	log *slog.Logger

	mu       sync.RWMutex
	cert     *tls.Certificate
	rootCAs  *x509.CertPool
	acmeHTTP httpServer
}

type httpServer interface {
	Shutdown() error
}

// New creates a certificate manager and ensures store directories exist.
func New(cfg *config.Config, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{cfg: cfg, log: log}
	for _, d := range []string{
		cfg.TLS.Dir,
		filepath.Join(cfg.TLS.Dir, "live"),
		filepath.Join(cfg.TLS.Dir, "ca"),
		filepath.Join(cfg.TLS.Dir, "acme"),
	} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, fmt.Errorf("certs dir %s: %w", d, err)
		}
	}
	if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

// Dir returns the certificate store root.
func (m *Manager) Dir() string { return m.cfg.TLS.Dir }

// CADir returns the custom CA directory.
func (m *Manager) CADir() string { return filepath.Join(m.cfg.TLS.Dir, "ca") }

// Reload re-reads certificates and CA pool from disk/config.
func (m *Manager) Reload() error {
	pool, err := m.buildRootCAs()
	if err != nil {
		return err
	}
	cert, err := m.loadActiveCertificate()
	if err != nil {
		// Not fatal if TLS is optional — keep nil cert.
		m.log.Debug("no active certificate", "err", err)
		cert = nil
	}
	m.mu.Lock()
	m.rootCAs = pool
	m.cert = cert
	m.mu.Unlock()
	return nil
}

// Certificate returns the active server certificate, if any.
func (m *Manager) Certificate() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert
}

// RootCAs returns the trust pool for outbound TLS verification.
func (m *Manager) RootCAs() *x509.CertPool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rootCAs
}

// ServerTLSConfig builds a tls.Config for SMTP STARTTLS / HTTPS.
// Returns nil if no certificate is loaded.
func (m *Manager) ServerTLSConfig() *tls.Config {
	cert := m.Certificate()
	if cert == nil {
		return nil
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1", "h2"},
	}
}

// ClientTLSConfig for outbound connections (relay).
func (m *Manager) ClientTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    m.RootCAs(),
		ServerName: serverName,
	}
}

func (m *Manager) loadActiveCertificate() (*tls.Certificate, error) {
	// Legacy paths on SMTP config take precedence.
	if m.cfg.Server.SMTP.TLSCert != "" && m.cfg.Server.SMTP.TLSKey != "" {
		return loadKeyPair(m.cfg.Server.SMTP.TLSCert, m.cfg.Server.SMTP.TLSKey)
	}

	name := m.cfg.TLS.Default
	profile, ok := m.cfg.TLS.Profiles[name]
	if !ok {
		// Fallback: live/fullchain.pem + live/privkey.pem
		certPath := filepath.Join(m.cfg.TLS.Dir, "live", "fullchain.pem")
		keyPath := filepath.Join(m.cfg.TLS.Dir, "live", "privkey.pem")
		if fileExists(certPath) && fileExists(keyPath) {
			return loadKeyPair(certPath, keyPath)
		}
		return nil, fmt.Errorf("no certificate profile %q and no live/ certs", name)
	}

	src := strings.ToLower(profile.Source)
	if src == "" {
		src = "file"
	}
	switch src {
	case "file":
		certPath := m.resolvePath(profile.Cert)
		keyPath := m.resolvePath(profile.Key)
		if profile.Cert == "" {
			certPath = filepath.Join(m.cfg.TLS.Dir, "live", "fullchain.pem")
		}
		if profile.Key == "" {
			keyPath = filepath.Join(m.cfg.TLS.Dir, "live", "privkey.pem")
		}
		return loadKeyPair(certPath, keyPath)
	case "selfsigned":
		domains := profile.Domains
		if len(domains) == 0 {
			domains = []string{m.cfg.Server.SMTP.Hostname}
		}
		return m.ensureSelfSigned(name, domains)
	case "acme":
		// ACME material is stored under live/ after issue/renew.
		certPath := filepath.Join(m.cfg.TLS.Dir, "live", "fullchain.pem")
		keyPath := filepath.Join(m.cfg.TLS.Dir, "live", "privkey.pem")
		return loadKeyPair(certPath, keyPath)
	default:
		return nil, fmt.Errorf("unknown cert source %q", src)
	}
}

func (m *Manager) resolvePath(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(m.cfg.TLS.Dir, p)
}

func (m *Manager) buildRootCAs() (*x509.CertPool, error) {
	var pool *x509.CertPool
	if m.cfg.TLS.CA.SystemEnabled() {
		sys, err := x509.SystemCertPool()
		if err != nil || sys == nil {
			pool = x509.NewCertPool()
		} else {
			pool = sys
		}
	} else {
		pool = x509.NewCertPool()
	}

	for _, f := range m.cfg.TLS.CA.ExtraFiles {
		path := f
		if !filepath.IsAbs(path) {
			path = filepath.Join(m.cfg.TLS.Dir, f)
		}
		if err := appendPEMFile(pool, path); err != nil {
			return nil, fmt.Errorf("ca file %s: %w", path, err)
		}
	}

	caDir := m.cfg.TLS.CA.ExtraDir
	if caDir == "" {
		caDir = m.CADir()
	} else if !filepath.IsAbs(caDir) {
		caDir = filepath.Join(m.cfg.TLS.Dir, caDir)
	}
	entries, err := os.ReadDir(caDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".pem") && !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".cer") {
			continue
		}
		if err := appendPEMFile(pool, filepath.Join(caDir, e.Name())); err != nil {
			m.log.Warn("skip ca file", "file", e.Name(), "err", err)
		}
	}
	return pool, nil
}

// List returns info about certificates under the store.
func (m *Manager) List() ([]Info, error) {
	var out []Info
	liveCert := filepath.Join(m.cfg.TLS.Dir, "live", "fullchain.pem")
	liveKey := filepath.Join(m.cfg.TLS.Dir, "live", "privkey.pem")
	if fileExists(liveCert) {
		info, err := inspectCert("live", liveCert, liveKey, "live")
		if err == nil {
			out = append(out, info)
		}
	}
	for name, p := range m.cfg.TLS.Profiles {
		src := p.Source
		if src == "" {
			src = "file"
		}
		certPath := m.resolvePath(p.Cert)
		keyPath := m.resolvePath(p.Key)
		if p.Cert == "" {
			certPath = liveCert
		}
		if !fileExists(certPath) {
			continue
		}
		info, err := inspectCert(name, certPath, keyPath, src)
		if err != nil {
			continue
		}
		// Avoid duplicate live entry.
		dup := false
		for _, existing := range out {
			if existing.CertPath == info.CertPath {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, info)
		}
	}
	return out, nil
}

// Import copies cert/key PEM into live/ (and optional named profile dir).
func (m *Manager) Import(certPEM, keyPEM []byte, name string) error {
	if name == "" {
		name = "live"
	}
	dir := filepath.Join(m.cfg.TLS.Dir, name)
	if name == "live" {
		dir = filepath.Join(m.cfg.TLS.Dir, "live")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	// Validate pair.
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		_ = os.Remove(certPath)
		_ = os.Remove(keyPath)
		return fmt.Errorf("invalid cert/key pair: %w", err)
	}
	return m.Reload()
}

// ImportFiles reads PEM files and imports them.
func (m *Manager) ImportFiles(certFile, keyFile, name string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	return m.Import(certPEM, keyPEM, name)
}

// Delete removes a named certificate directory (not ca/).
func (m *Manager) Delete(name string) error {
	if name == "" || name == "ca" || name == "acme" {
		return fmt.Errorf("refusing to delete %q", name)
	}
	dir := filepath.Join(m.cfg.TLS.Dir, name)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return m.Reload()
}

// AddCA copies a PEM CA file into the CA directory.
func (m *Manager) AddCA(srcPath, destName string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	if destName == "" {
		destName = filepath.Base(srcPath)
	}
	if !strings.HasSuffix(strings.ToLower(destName), ".pem") &&
		!strings.HasSuffix(strings.ToLower(destName), ".crt") {
		destName += ".pem"
	}
	dest := filepath.Join(m.CADir(), destName)
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return err
	}
	// Verify at least one cert parses.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		_ = os.Remove(dest)
		return fmt.Errorf("no certificates found in PEM")
	}
	return m.Reload()
}

// RemoveCA deletes a CA file from the CA directory.
func (m *Manager) RemoveCA(name string) error {
	path := filepath.Join(m.CADir(), name)
	if err := os.Remove(path); err != nil {
		return err
	}
	return m.Reload()
}

// ListCA returns CA filenames in the store.
func (m *Manager) ListCA() ([]string, error) {
	entries, err := os.ReadDir(m.CADir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	return names, nil
}

func (m *Manager) ensureSelfSigned(name string, domains []string) (*tls.Certificate, error) {
	dir := filepath.Join(m.cfg.TLS.Dir, name)
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if fileExists(certPath) && fileExists(keyPath) {
		return loadKeyPair(certPath, keyPath)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	certPEM, keyPEM, err := GenerateSelfSigned(domains, 365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	m.log.Info("generated self-signed certificate", "name", name, "domains", domains)
	return loadKeyPair(certPath, keyPath)
}

// GenerateSelfSigned creates a leaf certificate PEM pair.
func GenerateSelfSigned(domains []string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(0).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	if len(domains) == 0 {
		domains = []string{"localhost"}
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domains[0], Organization: []string{"mgw"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     domains,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

func loadKeyPair(certFile, keyFile string) (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func appendPEMFile(pool *x509.CertPool, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !pool.AppendCertsFromPEM(data) {
		return fmt.Errorf("no certificates in %s", path)
	}
	return nil
}

func inspectCert(name, certPath, keyPath, source string) (Info, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return Info{}, err
	}
	var leaf *x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		leaf = c
		break
	}
	if leaf == nil {
		return Info{}, fmt.Errorf("no certificate in %s", certPath)
	}
	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	return Info{
		Name:      name,
		Subject:   leaf.Subject.String(),
		Issuer:    leaf.Issuer.String(),
		NotBefore: leaf.NotBefore.UTC(),
		NotAfter:  leaf.NotAfter.UTC(),
		DNSNames:  leaf.DNSNames,
		Source:    source,
		CertPath:  certPath,
		KeyPath:   keyPath,
		DaysLeft:  days,
	}, nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// Close stops auxiliary ACME HTTP listener if running.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.acmeHTTP != nil {
		err := m.acmeHTTP.Shutdown()
		m.acmeHTTP = nil
		return err
	}
	return nil
}
