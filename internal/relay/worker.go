package relay

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/mailmsg"
	"github.com/rkislov/mailedge/internal/metrics"
	"github.com/rkislov/mailedge/internal/queue"
)

// Worker delivers queued messages via SMTP.
type Worker struct {
	cfg     *config.Config
	spool   *queue.Spool
	metrics *metrics.Registry
	log     *slog.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a relay worker pool (not started).
func New(cfg *config.Config, spool *queue.Spool, met *metrics.Registry, log *slog.Logger) *Worker {
	if log == nil {
		log = slog.Default()
	}
	return &Worker{cfg: cfg, spool: spool, metrics: met, log: log}
}

// Start launches background workers.
func (w *Worker) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)
	n := w.cfg.Relay.Workers
	if n <= 0 {
		n = 1
	}
	for i := 0; i < n; i++ {
		w.wg.Add(1)
		go w.loop(ctx, i)
	}
	w.log.Info("relay started", "workers", n)
}

// Stop waits for workers to finish.
func (w *Worker) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	w.wg.Wait()
	w.log.Info("relay stopped")
}

func (w *Worker) loop(ctx context.Context, id int) {
	defer w.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.drain(ctx)
		}
	}
}

func (w *Worker) drain(ctx context.Context) {
	msgs, err := w.spool.ClaimReady(10)
	if err != nil {
		w.log.Error("claim failed", "err", err)
		return
	}
	for _, msg := range msgs {
		if ctx.Err() != nil {
			// Put back for recovery on next start.
			_ = w.spool.Defer(msg, "shutdown", w.cfg.Relay.InitialBackoff, w.cfg.Relay.MaxBackoff, w.cfg.Relay.MaxAttempts)
			continue
		}
		w.deliverOne(ctx, msg)
	}
}

func (w *Worker) deliverOne(ctx context.Context, msg *mailmsg.Message) {
	data, err := w.spool.ReadData(msg)
	if err != nil {
		_ = w.spool.Bounce(msg, err.Error())
		w.metrics.Bounced.Add(1)
		return
	}
	err = w.send(ctx, msg, data)
	if err == nil {
		_ = w.spool.Complete(msg)
		w.metrics.Delivered.Add(1)
		return
	}
	w.log.Warn("delivery failed", "id", msg.ID, "err", err)
	if isPermanent(err) {
		_ = w.spool.Bounce(msg, err.Error())
		w.metrics.Bounced.Add(1)
		return
	}
	_ = w.spool.Defer(msg, err.Error(), w.cfg.Relay.InitialBackoff, w.cfg.Relay.MaxBackoff, w.cfg.Relay.MaxAttempts)
	w.metrics.Deferred.Add(1)
}

func (w *Worker) send(ctx context.Context, msg *mailmsg.Message, data []byte) error {
	_ = ctx
	for _, rcpt := range msg.To {
		host, err := w.resolveHost(rcpt)
		if err != nil {
			return err
		}
		addr := host
		if !strings.Contains(addr, ":") {
			addr = net.JoinHostPort(addr, "25")
		}
		if err := smtpSend(addr, w.cfg.Relay.Helo, msg.From, []string{rcpt}, data); err != nil {
			return fmt.Errorf("%s: %w", rcpt, err)
		}
	}
	return nil
}

func (w *Worker) resolveHost(rcpt string) (string, error) {
	if sh := strings.TrimSpace(w.cfg.Relay.SmartHost); sh != "" {
		return sh, nil
	}
	at := strings.LastIndex(rcpt, "@")
	if at < 0 || at == len(rcpt)-1 {
		return "", fmt.Errorf("invalid recipient: %s", rcpt)
	}
	domain := rcpt[at+1:]
	mxs, err := net.LookupMX(domain)
	if err != nil || len(mxs) == 0 {
		// Fallback to A/AAAA of the domain itself.
		return domain, nil
	}
	return strings.TrimSuffix(mxs[0].Host, "."), nil
}

func smtpSend(addr, helo, from string, to []string, data []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	client, err := smtp.NewClient(conn, hostOf(addr))
	if err != nil {
		return err
	}
	defer client.Close()

	if helo == "" {
		helo = "localhost"
	}
	if err := client.Hello(helo); err != nil {
		return err
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return err
		}
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(data); err != nil {
		_ = wc.Close()
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func isPermanent(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	// Rough SMTP permanent failure detection (5xx).
	for _, code := range []string{"550", "551", "552", "553", "554", "501", "503", "504", "521", "523"} {
		if strings.Contains(s, code) {
			return true
		}
	}
	return false
}
