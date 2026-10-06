package filter

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"regexp"
	"strings"
	"sync"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/intel"
	"github.com/rkislov/mailedge/internal/mailmsg"
)

var urlExtractRE = regexp.MustCompile(`(?i)https?://[^\s<>"'\)\]]+|www\.[^\s<>"'\)\]]+`)
var domainExtractRE = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b`)

// IOCFilter matches message artifacts against the Threat Intel store.
type IOCFilter struct {
	mu    sync.RWMutex
	cfg   config.IntelConfig
	store *intel.Store
}

// NewIOCFilter creates an IOC filter (store may be set later).
func NewIOCFilter(store *intel.Store) *IOCFilter {
	return &IOCFilter{store: store}
}

// SetStore attaches/replaces the IOC store.
func (f *IOCFilter) SetStore(store *intel.Store) {
	f.mu.Lock()
	f.store = store
	f.mu.Unlock()
}

func (f *IOCFilter) Name() string { return "intel" }

func (f *IOCFilter) Init(cfg *config.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cfg == nil {
		f.cfg = config.IntelConfig{}
		return nil
	}
	f.cfg = cfg.Filters.Intel
	return nil
}

func (f *IOCFilter) Close() error { return nil }

func (f *IOCFilter) Process(ctx context.Context, msg *mailmsg.Message, data []byte) (*mailmsg.Result, error) {
	f.mu.RLock()
	cfg := f.cfg
	store := f.store
	f.mu.RUnlock()
	if !cfg.Enabled || store == nil {
		return &mailmsg.Result{Action: "accept"}, nil
	}

	cands := collectIOCCandidates(msg, data)
	hit, err := store.LookupAny(ctx, cands)
	if err != nil {
		return nil, err
	}
	if hit == nil {
		return &mailmsg.Result{Action: "accept"}, nil
	}

	act := strings.ToLower(hit.Action)
	if act == "" {
		act = strings.ToLower(cfg.OnHit)
	}
	if act == "" {
		act = "reject"
	}
	reason := "ioc: " + hit.Type + "=" + hit.Value
	if hit.Threat != "" {
		reason += " (" + hit.Threat + ")"
	}
	return &mailmsg.Result{
		Action: act,
		Reason: reason,
		Tags:   []string{"ioc:" + hit.Type, "ioc-source:" + hit.Source},
		Details: map[string]string{
			"type":   hit.Type,
			"value":  hit.Value,
			"threat": hit.Threat,
			"source": hit.Source,
		},
	}, nil
}

func collectIOCCandidates(msg *mailmsg.Message, data []byte) []intel.IOC {
	var out []intel.IOC
	seen := map[string]bool{}
	add := func(typ, value string) {
		typ = intel.NormalizeType(typ)
		value = intel.NormalizeValue(typ, value)
		if typ == "" || value == "" {
			return
		}
		key := typ + "|" + value
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, intel.IOC{Type: typ, Value: value})
	}

	if msg != nil && msg.RemoteIP != "" {
		add(intel.TypeIP, msg.RemoteIP)
	}
	if msg != nil {
		addEmailParts(msg.From, add)
		for _, to := range msg.To {
			addEmailParts(to, add)
		}
	}

	raw := string(data)
	for _, u := range urlExtractRE.FindAllString(raw, 50) {
		add(intel.TypeURL, u)
		if host := hostFromURL(u); host != "" {
			add(intel.TypeDomain, host)
		}
	}
	for _, d := range domainExtractRE.FindAllString(raw, 50) {
		add(intel.TypeDomain, d)
	}

	// whole message hashes
	sum256 := sha256.Sum256(data)
	add(intel.TypeHash, hex.EncodeToString(sum256[:]))
	sum1 := sha1.Sum(data)
	add(intel.TypeHash, hex.EncodeToString(sum1[:]))
	sumMD5 := md5.Sum(data)
	add(intel.TypeHash, hex.EncodeToString(sumMD5[:]))

	for _, att := range extractAttachmentBytes(data) {
		h := sha256.Sum256(att)
		add(intel.TypeHash, hex.EncodeToString(h[:]))
		h1 := sha1.Sum(att)
		add(intel.TypeHash, hex.EncodeToString(h1[:]))
		hm := md5.Sum(att)
		add(intel.TypeHash, hex.EncodeToString(hm[:]))
	}
	return out
}

func addEmailParts(addr string, add func(typ, value string)) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		add(intel.TypeDomain, addr[i+1:])
	}
}

func hostFromURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "www.")
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, ":"); i >= 0 {
		u = u[:i]
	}
	return u
}

func extractAttachmentBytes(data []byte) [][]byte {
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
	var out [][]byte
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if !strings.Contains(strings.ToLower(p.Header.Get("Content-Disposition")), "attachment") && p.FileName() == "" {
			_ = p.Close()
			continue
		}
		b, err := io.ReadAll(io.LimitReader(p, 10<<20))
		_ = p.Close()
		if err != nil || len(b) == 0 {
			continue
		}
		out = append(out, b)
	}
	return out
}
