package smtpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/filter"
	"github.com/rkislov/mailedge/internal/mailmsg"
	"github.com/rkislov/mailedge/internal/metrics"
	mimeutil "github.com/rkislov/mailedge/internal/mime"
	"github.com/rkislov/mailedge/internal/policy"
	"github.com/rkislov/mailedge/internal/queue"
)

// Backend implements go-smtp Backend.
type Backend struct {
	cfg     *config.Config
	spool   *queue.Spool
	policy  *policy.Engine
	filters *filter.Chain
	metrics *metrics.Registry
	log     *slog.Logger
}

// NewBackend constructs the SMTP backend.
func NewBackend(cfg *config.Config, spool *queue.Spool, pol *policy.Engine, chain *filter.Chain, met *metrics.Registry, log *slog.Logger) *Backend {
	if log == nil {
		log = slog.Default()
	}
	return &Backend{cfg: cfg, spool: spool, policy: pol, filters: chain, metrics: met, log: log}
}

func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	remote := ""
	if c != nil && c.Conn() != nil {
		remote = c.Conn().RemoteAddr().String()
		if host, _, err := net.SplitHostPort(remote); err == nil {
			remote = host
		}
	}
	return &session{backend: b, remoteIP: remote}, nil
}

type session struct {
	backend  *Backend
	remoteIP string
	helo     string
	from     string
	to       []string
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	s.from = from
	s.to = nil
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	max := s.backend.cfg.Server.SMTP.MaxRecipients
	if max > 0 && len(s.to) >= max {
		s.backend.metrics.Rejected.Add(1)
		return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3}, Message: "too many recipients"}
	}
	s.to = append(s.to, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	max := s.backend.cfg.Server.SMTP.MaxMessageBytes
	var reader io.Reader = r
	if max > 0 {
		reader = io.LimitReader(r, max+1)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if max > 0 && int64(len(data)) > max {
		s.backend.metrics.Rejected.Add(1)
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "message too large"}
	}
	if len(s.to) == 0 {
		return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "no valid recipients"}
	}

	parsed, _ := mimeutil.Parse(data)
	msg := &mailmsg.Message{
		From:       s.from,
		To:         append([]string{}, s.to...),
		RemoteIP:   s.remoteIP,
		Helo:       s.helo,
		ReceivedAt: time.Now().UTC(),
	}
	if parsed != nil {
		msg.Subject = parsed.Subject
	}

	ctx := context.Background()
	polRes, err := s.backend.policy.Evaluate(ctx, msg, data)
	if err != nil {
		return err
	}
	if polRes != nil && polRes.Action == "reject" {
		s.backend.metrics.Rejected.Add(1)
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "rejected by policy"}
	}
	if polRes != nil && polRes.Action == "discard" {
		s.backend.metrics.Received.Add(1)
		s.backend.log.Info("discarded by policy", "from", msg.From)
		return nil
	}

	if s.backend.filters != nil {
		fres, err := s.backend.filters.Process(ctx, msg, data)
		if err != nil {
			return err
		}
		if fres != nil {
			switch fres.Action {
			case "reject":
				s.backend.metrics.Rejected.Add(1)
				reason := fres.Reason
				if reason == "" {
					reason = "rejected by filter"
				}
				return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: reason}
			case "discard":
				s.backend.metrics.Received.Add(1)
				return nil
			}
		}
	}

	if err := s.backend.spool.Enqueue(msg, data); err != nil {
		s.backend.log.Error("enqueue failed", "err", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "temporary local error"}
	}
	s.backend.metrics.Received.Add(1)
	return nil
}

func (s *session) Reset() {
	s.from = ""
	s.to = nil
}

func (s *session) Logout() error { return nil }

// Server wraps one or more go-smtp listeners.
type Server struct {
	backend   *Backend
	cfg       *config.Config
	log       *slog.Logger
	tlsConfig *tls.Config

	mu      sync.Mutex
	servers []*smtp.Server
}

// New creates an SMTP server that is not yet listening.
func New(cfg *config.Config, backend *Backend, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{backend: backend, cfg: cfg, log: log}
}

// SetTLSConfig enables STARTTLS / implicit TLS when non-nil.
func (s *Server) SetTLSConfig(tc *tls.Config) {
	s.tlsConfig = tc
}

func (s *Server) newSMTP(addr string) *smtp.Server {
	srv := smtp.NewServer(s.backend)
	srv.Addr = addr
	srv.Domain = s.cfg.Server.SMTP.Hostname
	srv.ReadTimeout = s.cfg.Server.SMTP.ReadTimeout
	srv.WriteTimeout = s.cfg.Server.SMTP.WriteTimeout
	srv.MaxMessageBytes = s.cfg.Server.SMTP.MaxMessageBytes
	srv.MaxRecipients = s.cfg.Server.SMTP.MaxRecipients
	srv.AllowInsecureAuth = true
	srv.EnableSMTPUTF8 = true
	if s.tlsConfig != nil && s.cfg.Server.SMTP.TLS {
		srv.TLSConfig = s.tlsConfig
	}
	return srv
}

// ListenAndServe starts plain/STARTTLS and optional implicit-TLS listeners.
func (s *Server) ListenAndServe(addrs []string) error {
	if len(addrs) == 0 && len(s.cfg.Server.SMTP.ImplicitTLSListen) == 0 {
		return errors.New("no listen addresses")
	}
	total := len(addrs) + len(s.cfg.Server.SMTP.ImplicitTLSListen)
	errCh := make(chan error, total)

	for _, addr := range addrs {
		addr := addr
		srv := s.newSMTP(addr)
		s.mu.Lock()
		s.servers = append(s.servers, srv)
		s.mu.Unlock()
		go func() {
			s.log.Info("smtp listening", "addr", addr, "starttls", srv.TLSConfig != nil)
			err := srv.ListenAndServe()
			if err != nil && !errors.Is(err, smtp.ErrServerClosed) {
				errCh <- err
				return
			}
			errCh <- nil
		}()
	}

	for _, addr := range s.cfg.Server.SMTP.ImplicitTLSListen {
		addr := addr
		if s.tlsConfig == nil {
			s.log.Error("implicit TLS listen requires certificate", "addr", addr)
			errCh <- errors.New("implicit TLS requires certificate")
			continue
		}
		srv := s.newSMTP(addr)
		srv.TLSConfig = s.tlsConfig
		s.mu.Lock()
		s.servers = append(s.servers, srv)
		s.mu.Unlock()
		go func() {
			s.log.Info("smtps listening", "addr", addr)
			err := srv.ListenAndServeTLS()
			if err != nil && !errors.Is(err, smtp.ErrServerClosed) {
				errCh <- err
				return
			}
			errCh <- nil
		}()
	}

	return <-errCh
}

// Shutdown gracefully stops all SMTP servers.
func (s *Server) Shutdown(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	for _, srv := range s.servers {
		if err := srv.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
