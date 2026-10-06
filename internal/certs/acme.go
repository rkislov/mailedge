package certs

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// ACMEStatus is a snapshot of ACME configuration / live cert.
type ACMEStatus struct {
	Enabled   bool     `json:"enabled"`
	Email     string   `json:"email"`
	Directory string   `json:"directory"`
	Challenge string   `json:"challenge"`
	Domains   []string `json:"domains"`
	HTTPBind  string   `json:"http_bind"`
	HasCert   bool     `json:"has_cert"`
	CertInfo  *Info    `json:"cert,omitempty"`
}

// ACMEStatus returns current ACME settings and whether a live cert exists.
func (m *Manager) ACMEStatus() ACMEStatus {
	st := ACMEStatus{
		Enabled:   m.cfg.TLS.ACME.Enabled,
		Email:     m.cfg.TLS.ACME.Email,
		Directory: m.cfg.TLS.ACME.Directory,
		Challenge: m.cfg.TLS.ACME.Challenge,
		Domains:   m.acmeDomains(),
		HTTPBind:  m.cfg.TLS.ACME.HTTPBind,
	}
	live := filepath.Join(m.cfg.TLS.Dir, "live", "fullchain.pem")
	key := filepath.Join(m.cfg.TLS.Dir, "live", "privkey.pem")
	if fileExists(live) {
		st.HasCert = true
		if info, err := inspectCert("live", live, key, "live"); err == nil {
			st.CertInfo = &info
		}
	}
	return st
}

func (m *Manager) acmeDomains() []string {
	if len(m.cfg.TLS.ACME.Domains) > 0 {
		return append([]string{}, m.cfg.TLS.ACME.Domains...)
	}
	if p, ok := m.cfg.TLS.Profiles[m.cfg.TLS.Default]; ok && len(p.Domains) > 0 {
		return append([]string{}, p.Domains...)
	}
	if h := m.cfg.Server.SMTP.Hostname; h != "" && h != "localhost" {
		return []string{h}
	}
	return nil
}

// IssueACME obtains a certificate via ACME and stores it under live/.
func (m *Manager) IssueACME(ctx context.Context, domains []string) (*Info, error) {
	if !m.cfg.TLS.ACME.AgreeTOS {
		return nil, fmt.Errorf("tls.acme.agree_tos must be true")
	}
	email := m.cfg.TLS.ACME.Email
	if email == "" {
		return nil, fmt.Errorf("tls.acme.email is required")
	}
	if len(domains) == 0 {
		domains = m.acmeDomains()
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains specified for ACME")
	}

	cacheDir := filepath.Join(m.cfg.TLS.Dir, "acme")
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return nil, err
	}

	client := &acme.Client{DirectoryURL: m.cfg.TLS.ACME.Directory}
	mgr := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		Email:      email,
		HostPolicy: autocert.HostWhitelist(domains...),
		Client:     client,
	}

	challenge := strings.ToLower(m.cfg.TLS.ACME.Challenge)
	var ln net.Listener
	var httpSrv *http.Server

	switch challenge {
	case "", "http-01":
		h := mgr.HTTPHandler(nil)
		httpSrv = &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
		bind := m.cfg.TLS.ACME.HTTPBind
		if bind == "" {
			bind = ":80"
		}
		var err error
		ln, err = net.Listen("tcp", bind)
		if err != nil {
			return nil, fmt.Errorf("acme http-01 listen %s: %w (нужны права на порт 80 или другой http_bind)", bind, err)
		}
		m.log.Info("acme http-01 listening", "addr", bind, "domains", domains)
		go func() { _ = httpSrv.Serve(ln) }()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = httpSrv.Shutdown(shutdownCtx)
			_ = ln.Close()
		}()
	case "tls-alpn-01":
		// autocert handles TLS-ALPN via GetCertificate; temporary listener on :443
		bind := ":443"
		tlsCfg := &tls.Config{GetCertificate: mgr.GetCertificate, NextProtos: []string{"acme-tls/1", "http/1.1"}}
		var err error
		ln, err = tls.Listen("tcp", bind, tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("acme tls-alpn-01 listen %s: %w", bind, err)
		}
		httpSrv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second}
		m.log.Info("acme tls-alpn-01 listening", "addr", bind, "domains", domains)
		go func() { _ = httpSrv.Serve(ln) }()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = httpSrv.Shutdown(shutdownCtx)
			_ = ln.Close()
		}()
	default:
		return nil, fmt.Errorf("unsupported challenge %q", challenge)
	}

	hello := &tls.ClientHelloInfo{ServerName: domains[0]}
	cert, err := mgr.GetCertificate(hello)
	if err != nil {
		return nil, fmt.Errorf("acme issue: %w", err)
	}

	if err := m.storeTLSCertificate(cert); err != nil {
		return nil, err
	}
	if err := m.Reload(); err != nil {
		return nil, err
	}

	info, err := inspectCert("live",
		filepath.Join(m.cfg.TLS.Dir, "live", "fullchain.pem"),
		filepath.Join(m.cfg.TLS.Dir, "live", "privkey.pem"),
		"acme")
	if err != nil {
		return nil, err
	}
	m.log.Info("acme certificate issued", "domains", domains, "not_after", info.NotAfter)
	_ = ctx
	return &info, nil
}

// RenewACME forces re-issue (autocert renews when needed; this re-runs GetCertificate).
func (m *Manager) RenewACME(ctx context.Context) (*Info, error) {
	return m.IssueACME(ctx, nil)
}

// StartACMEHTTP starts a long-lived HTTP-01 challenge handler (for server mode).
func (m *Manager) StartACMEHTTP() error {
	if !m.cfg.TLS.ACME.Enabled {
		return nil
	}
	if strings.ToLower(m.cfg.TLS.ACME.Challenge) == "tls-alpn-01" {
		return nil // handled via GetCertificate on TLS listeners
	}
	domains := m.acmeDomains()
	if len(domains) == 0 {
		return fmt.Errorf("acme enabled but no domains configured")
	}
	cacheDir := filepath.Join(m.cfg.TLS.Dir, "acme")
	_ = os.MkdirAll(cacheDir, 0o750)

	client := &acme.Client{DirectoryURL: m.cfg.TLS.ACME.Directory}
	mgr := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		Email:      m.cfg.TLS.ACME.Email,
		HostPolicy: autocert.HostWhitelist(domains...),
		Client:     client,
	}

	bind := m.cfg.TLS.ACME.HTTPBind
	if bind == "" {
		bind = ":80"
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return fmt.Errorf("acme http listen: %w", err)
	}
	srv := &http.Server{Handler: mgr.HTTPHandler(nil), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		m.log.Info("acme challenge server", "addr", bind)
		_ = srv.Serve(ln)
	}()
	m.mu.Lock()
	m.acmeHTTP = &acmeHTTPWrapper{srv: srv, ln: ln}
	m.mu.Unlock()

	// Warm certificate in background.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = ctx
		hello := &tls.ClientHelloInfo{ServerName: domains[0]}
		cert, err := mgr.GetCertificate(hello)
		if err != nil {
			m.log.Error("acme warm failed", "err", err)
			return
		}
		if err := m.storeTLSCertificate(cert); err != nil {
			m.log.Error("acme store failed", "err", err)
			return
		}
		_ = m.Reload()
		m.log.Info("acme certificate ready", "domain", domains[0])
	}()
	return nil
}

// AutocertManager returns an autocert.Manager when ACME is enabled (for GetCertificate).
func (m *Manager) AutocertManager() *autocert.Manager {
	if !m.cfg.TLS.ACME.Enabled {
		return nil
	}
	domains := m.acmeDomains()
	if len(domains) == 0 {
		return nil
	}
	cacheDir := filepath.Join(m.cfg.TLS.Dir, "acme")
	_ = os.MkdirAll(cacheDir, 0o750)
	return &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		Email:      m.cfg.TLS.ACME.Email,
		HostPolicy: autocert.HostWhitelist(domains...),
		Client:     &acme.Client{DirectoryURL: m.cfg.TLS.ACME.Directory},
	}
}

type acmeHTTPWrapper struct {
	srv *http.Server
	ln  net.Listener
}

func (w *acmeHTTPWrapper) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = w.srv.Shutdown(ctx)
	return w.ln.Close()
}

func (m *Manager) storeTLSCertificate(cert *tls.Certificate) error {
	if cert == nil || len(cert.Certificate) == 0 {
		return fmt.Errorf("empty certificate")
	}
	liveDir := filepath.Join(m.cfg.TLS.Dir, "live")
	if err := os.MkdirAll(liveDir, 0o750); err != nil {
		return err
	}

	var chain []byte
	for _, der := range cert.Certificate {
		block := pemBlock("CERTIFICATE", der)
		chain = append(chain, block...)
	}
	keyPEM, err := marshalPrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(liveDir, "fullchain.pem"), chain, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(liveDir, "privkey.pem"), keyPEM, 0o600)
}
