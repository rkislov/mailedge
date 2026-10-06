package filter

import (
	"context"
	"net/mail"
	"regexp"
	"strings"
	"sync"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/mailmsg"
)

var uriRE = regexp.MustCompile(`(?i)https?://[^\s<>"']+|www\.[^\s<>"']+`)

// Antispam is a lightweight scoring filter.
type Antispam struct {
	mu    sync.RWMutex
	cfg   config.AntispamConfig
	rules []compiledRule
}

type compiledRule struct {
	id     string
	weight float64
	header string
	re     *regexp.Regexp
	uri    bool
}

// NewAntispam creates an antispam filter.
func NewAntispam() *Antispam {
	return &Antispam{}
}

func (a *Antispam) Name() string { return "antispam" }

func (a *Antispam) Init(cfg *config.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cfg == nil {
		a.cfg = config.AntispamConfig{}
		a.rules = nil
		return nil
	}
	a.cfg = cfg.Filters.Antispam
	a.rules = nil
	for _, r := range a.cfg.Rules {
		if strings.TrimSpace(r.Regex) == "" {
			continue
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return err
		}
		w := r.Weight
		if w == 0 {
			w = 1
		}
		a.rules = append(a.rules, compiledRule{
			id:     r.ID,
			weight: w,
			header: r.Header,
			re:     re,
			uri:    r.URI,
		})
	}
	return nil
}

func (a *Antispam) Close() error { return nil }

func (a *Antispam) Process(_ context.Context, msg *mailmsg.Message, data []byte) (*mailmsg.Result, error) {
	a.mu.RLock()
	cfg := a.cfg
	rules := a.rules
	a.mu.RUnlock()
	if !cfg.Enabled || len(rules) == 0 {
		return &mailmsg.Result{Action: "accept"}, nil
	}

	headers, body := splitMIME(data)
	var score float64
	var hits []string

	for _, r := range rules {
		matched := false
		switch {
		case r.uri:
			matched = r.re.MatchString(strings.Join(uriRE.FindAllString(body, -1), "\n"))
		case r.header != "":
			val := headerValue(headers, r.header)
			if msg != nil && strings.EqualFold(r.header, "Subject") && val == "" {
				val = msg.Subject
			}
			matched = r.re.MatchString(val)
		default:
			matched = r.re.MatchString(body) || r.re.MatchString(string(data))
		}
		if matched {
			score += r.weight
			if r.id != "" {
				hits = append(hits, r.id)
			}
		}
	}

	res := &mailmsg.Result{
		Score:   score,
		Action:  "accept",
		Details: map[string]string{},
	}
	if len(hits) > 0 {
		res.Tags = append(res.Tags, "spam:"+strings.Join(hits, ","))
		res.Details["hits"] = strings.Join(hits, ",")
		res.Reason = "antispam score"
	}

	switch {
	case cfg.RejectScore > 0 && score >= cfg.RejectScore:
		res.Action = "reject"
		res.Reason = "antispam reject score"
	case cfg.QuarantineScore > 0 && score >= cfg.QuarantineScore:
		res.Action = "quarantine"
		res.Reason = "antispam quarantine score"
	case cfg.TagScore > 0 && score >= cfg.TagScore:
		res.Action = "tag"
		res.Tags = append(res.Tags, "X-Spam-Flag: YES")
		res.Reason = "antispam tag score"
	}
	return res, nil
}

func splitMIME(data []byte) (map[string]string, string) {
	headers := map[string]string{}
	raw := string(data)
	idx := strings.Index(raw, "\r\n\r\n")
	sep := "\r\n\r\n"
	if idx < 0 {
		idx = strings.Index(raw, "\n\n")
		sep = "\n\n"
	}
	if idx < 0 {
		return headers, raw
	}
	hdrBlock := raw[:idx]
	body := raw[idx+len(sep):]
	msg, err := mail.ReadMessage(strings.NewReader(hdrBlock + sep))
	if err == nil {
		for k, vals := range msg.Header {
			headers[httpCanonical(k)] = strings.Join(vals, " ")
		}
		return headers, body
	}
	for _, line := range strings.Split(hdrBlock, "\n") {
		line = strings.TrimRight(line, "\r")
		if i := strings.IndexByte(line, ':'); i > 0 {
			k := httpCanonical(strings.TrimSpace(line[:i]))
			v := strings.TrimSpace(line[i+1:])
			headers[k] = v
		}
	}
	return headers, body
}

func headerValue(h map[string]string, name string) string {
	if v, ok := h[httpCanonical(name)]; ok {
		return v
	}
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func httpCanonical(s string) string {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
	}
	return strings.Join(parts, "-")
}
