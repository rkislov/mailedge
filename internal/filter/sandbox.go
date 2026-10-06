package filter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/mailmsg"
)

// Sandbox submits content to an HTTP detonation / sandbox API.
type Sandbox struct {
	mu     sync.RWMutex
	cfg    config.SandboxConfig
	cache  map[string]sandboxCacheEntry
	client *http.Client
	now    func() time.Time
	// Do is overridable in tests.
	Do func(req *http.Request) (*http.Response, error)
}

type sandboxCacheEntry struct {
	verdict string
	threat  string
	until   time.Time
}

type sandboxRequest struct {
	SHA256   string `json:"sha256"`
	Filename string `json:"filename"`
	Content  string `json:"content_base64"`
}

type sandboxResponse struct {
	Verdict string  `json:"verdict"` // clean | malicious | suspicious
	Threat  string  `json:"threat"`
	Score   float64 `json:"score"`
}

// NewSandbox creates a sandbox filter.
func NewSandbox() *Sandbox {
	return &Sandbox{
		cache:  make(map[string]sandboxCacheEntry),
		client: &http.Client{},
		now:    time.Now,
	}
}

func (s *Sandbox) Name() string { return "sandbox" }

func (s *Sandbox) Init(cfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg == nil {
		s.cfg = config.SandboxConfig{}
		return nil
	}
	s.cfg = cfg.Filters.Sandbox
	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	s.client = &http.Client{Timeout: timeout}
	return nil
}

func (s *Sandbox) Close() error { return nil }

func (s *Sandbox) Process(ctx context.Context, msg *mailmsg.Message, data []byte) (*mailmsg.Result, error) {
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	if !cfg.Enabled || strings.TrimSpace(cfg.URL) == "" {
		return &mailmsg.Result{Action: "accept"}, nil
	}

	payloads := sandboxPayloads(data, cfg)
	if len(payloads) == 0 {
		return &mailmsg.Result{Action: "accept", Reason: "sandbox: nothing to scan"}, nil
	}

	var worst *mailmsg.Result
	for _, p := range payloads {
		res, err := s.scanOne(ctx, cfg, p.name, p.data)
		if err != nil {
			act := strings.ToLower(cfg.OnUnavailable)
			if act == "" || act == "pass" {
				return &mailmsg.Result{
					Action:  "accept",
					Reason:  "sandbox unavailable",
					Tags:    []string{"sandbox:unavailable"},
					Details: map[string]string{"error": err.Error()},
				}, nil
			}
			return &mailmsg.Result{
				Action:  act,
				Reason:  "sandbox unavailable: " + err.Error(),
				Tags:    []string{"sandbox:unavailable"},
				Details: map[string]string{"error": err.Error()},
			}, nil
		}
		if worst == nil || severity(res.Action) > severity(worst.Action) {
			worst = res
		}
		if res.Action == "reject" || res.Action == "quarantine" {
			return res, nil
		}
	}
	if worst == nil {
		return &mailmsg.Result{Action: "accept"}, nil
	}
	return worst, nil
}

type namedBlob struct {
	name string
	data []byte
}

func sandboxPayloads(data []byte, cfg config.SandboxConfig) []namedBlob {
	if cfg.AttachmentsOnly {
		atts := extractAttachments(data, cfg.MaxBytes)
		if len(atts) > 0 {
			return atts
		}
		return nil
	}
	body := data
	if cfg.MaxBytes > 0 && int64(len(body)) > cfg.MaxBytes {
		body = body[:cfg.MaxBytes]
	}
	out := []namedBlob{{name: "message.eml", data: body}}
	out = append(out, extractAttachments(data, cfg.MaxBytes)...)
	return out
}

func extractAttachments(data []byte, maxBytes int64) []namedBlob {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	ct := msg.Header.Get("Content-Type")
	media, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.HasPrefix(media, "multipart/") {
		return nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil
	}
	mr := multipart.NewReader(msg.Body, boundary)
	var out []namedBlob
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		disp := p.Header.Get("Content-Disposition")
		if !strings.Contains(strings.ToLower(disp), "attachment") && p.FileName() == "" {
			_ = p.Close()
			continue
		}
		name := p.FileName()
		if name == "" {
			name = "attachment.bin"
		}
		b, err := io.ReadAll(io.LimitReader(p, func() int64 {
			if maxBytes > 0 {
				return maxBytes + 1
			}
			return 32 << 20
		}()))
		_ = p.Close()
		if err != nil {
			continue
		}
		if maxBytes > 0 && int64(len(b)) > maxBytes {
			continue
		}
		out = append(out, namedBlob{name: name, data: b})
	}
	return out
}

func (s *Sandbox) scanOne(ctx context.Context, cfg config.SandboxConfig, filename string, data []byte) (*mailmsg.Result, error) {
	sum := sha256.Sum256(data)
	key := hex.EncodeToString(sum[:])

	s.mu.RLock()
	if e, ok := s.cache[key]; ok && s.now().Before(e.until) {
		s.mu.RUnlock()
		return verdictResult(cfg, e.verdict, e.threat, key), nil
	}
	s.mu.RUnlock()

	body, _ := json.Marshal(sandboxRequest{
		SHA256:   key,
		Filename: filename,
		Content:  base64.StdEncoding.EncodeToString(data),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mgw-sandbox/1.0")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		req.Header.Set("X-API-Key", cfg.APIKey)
	}

	do := s.Do
	if do == nil {
		do = s.client.Do
	}
	resp, err := do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("sandbox http %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var parsed sandboxResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("sandbox decode: %w", err)
	}
	verdict := strings.ToLower(strings.TrimSpace(parsed.Verdict))
	if verdict == "" {
		verdict = "clean"
	}

	s.mu.Lock()
	s.cache[key] = sandboxCacheEntry{
		verdict: verdict,
		threat:  parsed.Threat,
		until:   s.now().Add(cfg.CacheTTL),
	}
	s.mu.Unlock()

	return verdictResult(cfg, verdict, parsed.Threat, key), nil
}

func verdictResult(cfg config.SandboxConfig, verdict, threat, sha string) *mailmsg.Result {
	res := &mailmsg.Result{
		Action: "accept",
		Tags:   []string{"sandbox:" + verdict},
		Details: map[string]string{
			"verdict": verdict,
			"sha256":  sha,
		},
	}
	if threat != "" {
		res.Details["threat"] = threat
		res.Reason = "sandbox: " + threat
	}
	switch verdict {
	case "malicious", "malware", "infected":
		act := strings.ToLower(cfg.OnMalicious)
		if act == "" {
			act = "reject"
		}
		res.Action = act
		if res.Reason == "" {
			res.Reason = "sandbox: malicious"
		}
	case "suspicious", "unknown":
		act := strings.ToLower(cfg.OnSuspicious)
		if act == "" {
			act = "tag"
		}
		res.Action = act
		if res.Reason == "" {
			res.Reason = "sandbox: suspicious"
		}
	default:
		res.Action = "accept"
	}
	return res
}

func severity(action string) int {
	switch strings.ToLower(action) {
	case "reject":
		return 40
	case "quarantine", "hold":
		return 30
	case "discard":
		return 20
	case "tag":
		return 10
	default:
		return 0
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
