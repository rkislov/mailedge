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

	"github.com/rkislov/mailedge/internal/auth"
	"github.com/rkislov/mailedge/internal/certs"
	"github.com/rkislov/mailedge/internal/config"
	dkimkeys "github.com/rkislov/mailedge/internal/dkim"
	"github.com/rkislov/mailedge/internal/domains"
	"github.com/rkislov/mailedge/internal/filter"
	"github.com/rkislov/mailedge/internal/logging"
	"github.com/rkislov/mailedge/internal/metrics"
	"github.com/rkislov/mailedge/internal/policy"
	"github.com/rkislov/mailedge/internal/quarantine"
	"github.com/rkislov/mailedge/internal/queue"
	"github.com/rkislov/mailedge/internal/relay"
	smtpserver "github.com/rkislov/mailedge/internal/smtp"
	"github.com/rkislov/mailedge/internal/storage"
	"github.com/rkislov/mailedge/internal/storage/sqlite"
	"github.com/rkislov/mailedge/internal/version"
	"github.com/rkislov/mailedge/internal/web"
	"github.com/rkislov/mailedge/internal/web/admin"
)

// App is the process-level composition root.
type App struct {
	cfg     *config.Config
	cfgPath string
	cfgMu   sync.RWMutex
	log     *slog.Logger
	spool   *queue.Spool
	store   storage.Storage
	db      *sqlite.DB
	certs   *certs.Manager
	metrics *metrics.Registry
	history *metrics.History
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
func New(cfg *config.Config, cfgPath string) (*App, error) {
	log := logging.Setup(cfg.Logging.Level, cfg.Logging.Format)

	if err := os.MkdirAll(cfg.Storage.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}

	dbPath := cfg.Storage.SQLite.Path
	if dbPath == "" {
		dbPath = filepath.Join(cfg.Storage.DataDir, "mgw.db")
	}
	db, err := sqlite.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("sqlite: %w", err)
	}

	certMgr, err := certs.New(cfg, log)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("certs: %w", err)
	}

	spool, err := queue.New(cfg.Storage.DataDir, log)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	n, err := spool.RecoverActive()
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("recover active: %w", err)
	}
	if n > 0 {
		log.Info("recovered active messages", "count", n)
	}

	store, err := storage.Open(cfg.Storage.Driver)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	authSvc := auth.New(db.SQL())
	domStore := domains.NewStore(db.SQL())
	dkimMgr, err := dkimkeys.New(db.SQL(), cfg.Storage.DataDir)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("dkim: %w", err)
	}

	met := metrics.New()
	hist := metrics.NewHistory(met)
	hist.SetQueue(func() map[string]int {
		s, err := spool.Stats()
		if err != nil {
			return nil
		}
		return s
	})
	pol := policy.New(cfg)
	chain, err := filter.BuildChain(cfg)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	qstore, err := quarantine.New(cfg.Storage.DataDir)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("quarantine: %w", err)
	}

	backend := smtpserver.NewBackend(cfg, spool, pol, chain, met, log)
	backend.SetDomains(domStore)
	backend.SetQuarantine(qstore)
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
	rel.SetRoutes(domStore)
	rel.SetSigner(dkimMgr)

	app := &App{
		cfg:     cfg,
		cfgPath: cfgPath,
		log:     log,
		spool:   spool,
		store:   store,
		db:      db,
		certs:   certMgr,
		metrics: met,
		history: hist,
		smtp:    smtpSrv,
		relay:   rel,
		started: time.Now().UTC(),
	}

	webHandler, err := web.NewHandler(spool, met, cfg.Server.SMTP.Hostname)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("web: %w", err)
	}
	adminHandler, err := admin.New(admin.Deps{
		CfgPath:     cfgPath,
		Cfg:         cfg,
		CfgMu:       &app.cfgMu,
		Auth:        authSvc,
		Certs:       certMgr,
		Domains:     domStore,
		DKIM:        dkimMgr,
		Spool:       spool,
		Metrics:     met,
		History:     hist,
		Policy:      pol,
		Filters:     chain,
		Quarantine:  qstore,
		Log:         log,
		Started:     app.started,
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("admin: %w", err)
	}

	mux := http.NewServeMux()
	webHandler.Mount(mux)
	adminHandler.Mount(mux)

	httpSrv := &http.Server{
		Addr:              cfg.Server.Web.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if cfg.Server.Web.TLS {
		if tlsCfg == nil {
			_ = db.Close()
			return nil, fmt.Errorf("server.web.tls=true, но сертификат не найден (см. tls.profiles / mgw cert)")
		}
		httpSrv.TLSConfig = tlsCfg.Clone()
	}
	app.httpSrv = httpSrv
	return app, nil
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

	if a.history != nil {
		a.history.Start(ctx.Done())
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
		"admin", "/admin",
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
	if a.db != nil {
		_ = a.db.Close()
	}
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

// WriteStatusJSON writes status for CLI `server status`.
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
