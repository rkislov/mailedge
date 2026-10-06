package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rkislov/mailedge/internal/certs"
	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/filter"
	"github.com/rkislov/mailedge/internal/logging"
	"github.com/rkislov/mailedge/internal/metrics"
	"github.com/rkislov/mailedge/internal/policy"
	"github.com/rkislov/mailedge/internal/queue"
	"github.com/rkislov/mailedge/internal/relay"
	smtpserver "github.com/rkislov/mailedge/internal/smtp"
	"github.com/rkislov/mailedge/internal/storage"
	"github.com/rkislov/mailedge/internal/version"
	"github.com/rkislov/mailedge/internal/web"
)

// App is the process-level composition root.
type App struct {
	cfg     *config.Config
	log     *slog.Logger
	spool   *queue.Spool
	store   storage.Storage
	certs   *certs.Manager
	metrics *metrics.Registry
	smtp    *smtpserver.Server
	relay   *relay.Worker
	httpSrv *http.Server
	started time.Time

	mu      sync.Mutex
	running bool
}

// Status is a serializable process status snapshot.
type Status struct {
	Running   bool             `json:"running"`
	Version   string           `json:"version"`
	StartedAt time.Time        `json:"started_at,omitempty"`
	Uptime    string           `json:"uptime,omitempty"`
	Hostname  string           `json:"hostname"`
	SMTP      []string         `json:"smtp_listen"`
	Web       string           `json:"web_listen"`
	TLS       bool             `json:"tls"`
	Metrics   map[string]int64 `json:"metrics,omitempty"`
	Queue     map[string]int   `json:"queue,omitempty"`
}

// New builds an App from config (does not start listeners).
func New(cfg *config.Config) (*App, error) {
	log := logging.Setup(cfg.Logging.Level, cfg.Logging.Format)

	if err := os.MkdirAll(cfg.Storage.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}

	certMgr, err := certs.New(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("certs: %w", err)
	}

	spool, err := queue.New(cfg.Storage.DataDir, log)
	if err != nil {
		return nil, err
	}
	n, err := spool.RecoverActive()
	if err != nil {
		return nil, fmt.Errorf("recover active: %w", err)
	}
	if n > 0 {
		log.Info("recovered active messages", "count", n)
	}

	store, err := storage.Open(cfg.Storage.Driver)
	if err != nil {
		return nil, err
	}

	met := metrics.New()
	pol := policy.New(cfg)
	chain := filter.NewChain(&filter.Noop{})
	if err := chain.Init(cfg); err != nil {
		return nil, err
	}

	backend := smtpserver.NewBackend(cfg, spool, pol, chain, met, log)
	smtpSrv := smtpserver.New(cfg, backend, log)

	tlsCfg := certMgr.ServerTLSConfig()
	if am := certMgr.AutocertManager(); am != nil {
		if tlsCfg == nil {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		tlsCfg.GetCertificate = am.GetCertificate
		tlsCfg.NextProtos = append(tlsCfg.NextProtos, "acme-tls/1")
	}
	if tlsCfg != nil {
		smtpSrv.SetTLSConfig(tlsCfg)
	} else if cfg.Server.SMTP.TLS {
		log.Warn("server.smtp.tls=true, но сертификат не загружен — STARTTLS отключён")
	}

	rel := relay.New(cfg, spool, met, log)

	webHandler, err := web.NewHandler(spool, met, cfg.Server.SMTP.Hostname)
	if err != nil {
		return nil, fmt.Errorf("web: %w", err)
	}
	mux := http.NewServeMux()
	webHandler.Mount(mux)

	httpSrv := &http.Server{
		Addr:              cfg.Server.Web.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if cfg.Server.Web.TLS {
		if tlsCfg == nil {
			return nil, fmt.Errorf("server.web.tls=true, но сертификат не найден (см. tls.profiles / mgw cert)")
		}
		httpSrv.TLSConfig = tlsCfg.Clone()
	}

	return &App{
		cfg:     cfg,
		log:     log,
		spool:   spool,
		store:   store,
		certs:   certMgr,
		metrics: met,
		smtp:    smtpSrv,
		relay:   rel,
		httpSrv: httpSrv,
	}, nil
}

// Run starts all services and blocks until ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	a.mu.Lock()
	a.running = true
	a.started = time.Now().UTC()
	a.mu.Unlock()

	if a.cfg.Server.PIDFile != "" {
		if err := writePID(a.cfg.Server.PIDFile); err != nil {
			a.log.Warn("pid file", "err", err)
		} else {
			defer func() { _ = os.Remove(a.cfg.Server.PIDFile) }()
		}
	}

	if err := a.certs.StartACMEHTTP(); err != nil {
		a.log.Warn("acme http", "err", err)
	}

	a.relay.Start(ctx)

	errCh := make(chan error, 2)
	go func() {
		if err := a.smtp.ListenAndServe(a.cfg.Server.SMTP.Listen); err != nil {
			errCh <- fmt.Errorf("smtp: %w", err)
		}
	}()
	go func() {
		a.log.Info("web listening", "addr", a.cfg.Server.Web.Listen, "tls", a.cfg.Server.Web.TLS)
		var err error
		if a.cfg.Server.Web.TLS {
			err = a.httpSrv.ListenAndServeTLS("", "")
		} else {
			err = a.httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("web: %w", err)
		}
	}()

	a.log.Info("mgw started",
		"version", version.Version,
		"smtp", a.cfg.Server.SMTP.Listen,
		"web", a.cfg.Server.Web.Listen,
		"tls_cert", a.certs.Certificate() != nil,
	)

	select {
	case <-ctx.Done():
		return a.Shutdown(context.Background())
	case err := <-errCh:
		_ = a.Shutdown(context.Background())
		return err
	}
}

// Shutdown stops relay, SMTP, and HTTP gracefully.
func (a *App) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		return nil
	}
	a.running = false
	a.log.Info("shutting down")

	a.relay.Stop()
	_ = a.smtp.Shutdown(ctx)
	_ = a.certs.Close()

	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = a.httpSrv.Shutdown(shutdownCtx)

	if n, err := a.spool.RecoverActive(); err == nil && n > 0 {
		a.log.Info("parked active messages on shutdown", "count", n)
	}
	_ = a.store.Close()
	a.log.Info("stopped")
	return nil
}

// Snapshot returns current status.
func (a *App) Snapshot() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := Status{
		Running:  a.running,
		Version:  version.Version,
		Hostname: a.cfg.Server.SMTP.Hostname,
		SMTP:     a.cfg.Server.SMTP.Listen,
		Web:      a.cfg.Server.Web.Listen,
		TLS:      a.certs.Certificate() != nil,
		Metrics:  a.metrics.Snapshot(),
	}
	if a.running {
		st.StartedAt = a.started
		st.Uptime = time.Since(a.started).Truncate(time.Second).String()
	}
	if q, err := a.spool.Stats(); err == nil {
		st.Queue = q
	}
	return st
}

// WriteStatusJSON writes status for CLI `server status` via a status file or stdout helper.
func WriteStatusJSON(w interface{ Write([]byte) (int, error) }, st Status) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func writePID(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644)
}

// IsPortOpen is a lightweight probe used by status command.
func IsPortOpen(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
