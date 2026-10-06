package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rkislov/mailedge/internal/config"
)

// Feeder periodically pulls ThreatFox / qfeed into the store.
type Feeder struct {
	store  *Store
	cfg    func() config.IntelConfig
	log    *slog.Logger
	client *http.Client
}

// NewFeeder creates a feed updater.
func NewFeeder(store *Store, cfgFn func() config.IntelConfig, log *slog.Logger) *Feeder {
	if log == nil {
		log = slog.Default()
	}
	return &Feeder{
		store:  store,
		cfg:    cfgFn,
		log:    log,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

// Start runs refresh loops until ctx is done.
func (f *Feeder) Start(ctx context.Context) {
	go f.loop(ctx)
}

func (f *Feeder) loop(ctx context.Context) {
	// initial refresh shortly after start
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}
	f.refreshSafe(ctx)
	for {
		cfg := f.cfg()
		interval := cfg.RefreshInterval
		if interval <= 0 {
			interval = time.Hour
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			f.refreshSafe(ctx)
		}
	}
}

func (f *Feeder) refreshSafe(ctx context.Context) {
	n, err := f.Refresh(ctx)
	if err != nil {
		f.log.Warn("intel refresh", "err", err)
		return
	}
	if n > 0 {
		f.log.Info("intel refresh", "upserted", n)
	}
}

// Refresh pulls all enabled feeds once.
func (f *Feeder) Refresh(ctx context.Context) (int, error) {
	cfg := f.cfg()
	if !cfg.Enabled {
		return 0, nil
	}
	total := 0
	if cfg.ThreatFox.Enabled {
		n, err := f.pullThreatFox(ctx, cfg.ThreatFox)
		if err != nil {
			return total, fmt.Errorf("threatfox: %w", err)
		}
		total += n
	}
	if cfg.QFeed.Enabled && cfg.QFeed.URL != "" {
		n, err := f.pullQFeed(ctx, cfg.QFeed)
		if err != nil {
			return total, fmt.Errorf("qfeed: %w", err)
		}
		total += n
	}
	return total, nil
}

type threatFoxReq struct {
	Query string `json:"query"`
	Days  int    `json:"days"`
}

type threatFoxResp struct {
	QueryStatus string `json:"query_status"`
	Data        []struct {
		IOC      string `json:"ioc"`
		IOCType  string `json:"ioc_type"`
		Threat   string `json:"threat_type"`
		Malware  string `json:"malware"`
		MalwarePrintable string `json:"malware_printable"`
	} `json:"data"`
}

func (f *Feeder) pullThreatFox(ctx context.Context, c config.ThreatFoxConfig) (int, error) {
	url := c.URL
	if url == "" {
		url = "https://threatfox-api.abuse.ch/api/v1/"
	}
	days := c.Days
	if days <= 0 {
		days = 1
	}
	body, _ := json.Marshal(threatFoxReq{Query: "get_iocs", Days: days})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mgw-intel/1.0")
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var parsed threatFoxResp
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return 0, err
	}
	if parsed.QueryStatus != "" && parsed.QueryStatus != "ok" {
		return 0, fmt.Errorf("query_status=%s", parsed.QueryStatus)
	}
	list := make([]IOC, 0, len(parsed.Data))
	for _, d := range parsed.Data {
		threat := d.MalwarePrintable
		if threat == "" {
			threat = d.Malware
		}
		if threat == "" {
			threat = d.Threat
		}
		list = append(list, IOC{
			Type:   d.IOCType,
			Value:  d.IOC,
			Threat: threat,
			Source: "threatfox",
		})
	}
	return f.store.BulkUpsert(ctx, list)
}

type qfeedItem struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	IOC    string `json:"ioc"`
	Threat string `json:"threat"`
	Source string `json:"source"`
}

func (f *Feeder) pullQFeed(ctx context.Context, c config.QFeedConfig) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "mgw-intel/1.0")
	if c.AuthHeader != "" {
		// "Authorization: Bearer xxx" or raw "Bearer xxx"
		if strings.Contains(c.AuthHeader, ":") {
			parts := strings.SplitN(c.AuthHeader, ":", 2)
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		} else {
			req.Header.Set("Authorization", c.AuthHeader)
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var items []qfeedItem
	if err := json.Unmarshal(raw, &items); err != nil {
		// try wrapped {"data":[...]}
		var wrap struct {
			Data []qfeedItem `json:"data"`
		}
		if err2 := json.Unmarshal(raw, &wrap); err2 != nil {
			return 0, err
		}
		items = wrap.Data
	}
	list := make([]IOC, 0, len(items))
	for _, it := range items {
		val := it.Value
		if val == "" {
			val = it.IOC
		}
		src := it.Source
		if src == "" {
			src = "qfeed"
		}
		list = append(list, IOC{Type: it.Type, Value: val, Threat: it.Threat, Source: src})
	}
	return f.store.BulkUpsert(ctx, list)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
