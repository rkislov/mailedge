package filter

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/filter/icap"
	"github.com/rkislov/mailedge/internal/mailmsg"
)

// AV scans messages via ICAP RESPMOD with failover across servers.
type AV struct {
	mu      sync.RWMutex
	cfg     config.AVConfig
	clients []*icap.Client
}

// NewAV creates an antivirus filter.
func NewAV() *AV {
	return &AV{}
}

func (a *AV) Name() string { return "av" }

func (a *AV) Init(cfg *config.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clients = nil
	if cfg == nil {
		a.cfg = config.AVConfig{}
		return nil
	}
	a.cfg = cfg.Filters.AV
	for _, s := range a.cfg.Servers {
		if strings.TrimSpace(s.Addr) == "" {
			continue
		}
		svc := s.Service
		if svc == "" {
			svc = "avscan"
		}
		a.clients = append(a.clients, &icap.Client{
			Addr:    s.Addr,
			Service: svc,
			TLS:     s.TLS,
			Timeout: a.cfg.Timeout,
		})
	}
	return nil
}

func (a *AV) Close() error { return nil }

func (a *AV) Process(ctx context.Context, msg *mailmsg.Message, data []byte) (*mailmsg.Result, error) {
	a.mu.RLock()
	cfg := a.cfg
	clients := a.clients
	a.mu.RUnlock()
	if !cfg.Enabled || len(clients) == 0 {
		return &mailmsg.Result{Action: "accept"}, nil
	}
	body := data
	if cfg.MaxBytes > 0 && int64(len(body)) > cfg.MaxBytes {
		body = body[:cfg.MaxBytes]
	}
	name := "message.eml"
	if msg != nil && msg.ID != "" {
		name = msg.ID + ".eml"
	}

	var lastErr error
	for _, c := range clients {
		scanCtx := ctx
		var cancel context.CancelFunc
		if cfg.Timeout > 0 {
			scanCtx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		}
		res, err := c.RESPMOD(scanCtx, name, body)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			lastErr = err
			continue
		}
		if res.Infected {
			act := strings.ToLower(cfg.OnInfected)
			if act == "" {
				act = "reject"
			}
			threat := res.Threat
			if threat == "" {
				threat = "malware"
			}
			return &mailmsg.Result{
				Action: act,
				Reason: "av: " + threat,
				Tags:   []string{"av:infected", "threat:" + threat},
				Details: map[string]string{
					"threat": threat,
					"icap":   c.Addr,
					"status": fmt.Sprintf("%d", res.Status),
				},
			}, nil
		}
		return &mailmsg.Result{
			Action: "accept",
			Tags:   []string{"av:clean"},
			Details: map[string]string{
				"icap":   c.Addr,
				"status": fmt.Sprintf("%d", res.Status),
			},
		}, nil
	}

	act := strings.ToLower(cfg.OnUnavailable)
	if act == "" || act == "pass" {
		return &mailmsg.Result{
			Action:  "accept",
			Reason:  "av unavailable",
			Tags:    []string{"av:unavailable"},
			Details: map[string]string{"error": errString(lastErr)},
		}, nil
	}
	return &mailmsg.Result{
		Action:  act,
		Reason:  "av unavailable: " + errString(lastErr),
		Tags:    []string{"av:unavailable"},
		Details: map[string]string{"error": errString(lastErr)},
	}, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
