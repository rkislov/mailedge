package policy

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/mailmsg"
)

// Engine evaluates ordered policy rules then the default action.
type Engine struct {
	mu  sync.RWMutex
	cfg *config.Config
}

// New creates a policy engine from config.
func New(cfg *config.Config) *Engine {
	return &Engine{cfg: cfg}
}

// SetConfig replaces the live config pointer (e.g. after admin save).
func (e *Engine) SetConfig(cfg *config.Config) {
	e.mu.Lock()
	e.cfg = cfg
	e.mu.Unlock()
}

// Evaluate returns the policy decision for a message.
func (e *Engine) Evaluate(_ context.Context, msg *mailmsg.Message, data []byte) (*mailmsg.Result, error) {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	if cfg == nil {
		return &mailmsg.Result{Action: "accept", Reason: "no config"}, nil
	}

	rules := append([]config.PolicyRule(nil), cfg.Policy.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	size := int64(len(data))
	if msg != nil && msg.Size > 0 {
		size = msg.Size
	}

	for _, rule := range rules {
		if !rule.PolicyRuleEnabled() {
			continue
		}
		ok, err := matchRule(rule.Match, msg, size)
		if err != nil {
			return nil, fmt.Errorf("policy rule %q: %w", rule.ID, err)
		}
		if !ok {
			continue
		}
		action := strings.ToLower(rule.Action)
		if action == "" {
			action = "accept"
		}
		res := &mailmsg.Result{
			Action: action,
			Reason: rule.Reason,
			Details: map[string]string{
				"rule": rule.ID,
			},
		}
		if res.Reason == "" {
			res.Reason = "policy rule " + rule.ID
		}
		if rule.Tag != "" {
			res.Tags = append(res.Tags, rule.Tag)
		}
		if action == "tag" {
			res.Action = "tag"
		}
		return res, nil
	}

	action := strings.ToLower(cfg.Policy.DefaultAction)
	if action == "" {
		action = "accept"
	}
	return &mailmsg.Result{
		Action: action,
		Reason: "default policy",
	}, nil
}

func matchRule(m config.PolicyMatch, msg *mailmsg.Message, size int64) (bool, error) {
	if msg == nil {
		msg = &mailmsg.Message{}
	}
	if m.From != "" && !globMatch(m.From, msg.From) {
		return false, nil
	}
	if m.To != "" {
		hit := false
		for _, to := range msg.To {
			if globMatch(m.To, to) {
				hit = true
				break
			}
		}
		if !hit {
			return false, nil
		}
	}
	if m.Helo != "" && !globMatch(m.Helo, msg.Helo) {
		return false, nil
	}
	if m.RemoteIP != "" && !ipMatch(m.RemoteIP, msg.RemoteIP) {
		return false, nil
	}
	if m.SubjectRe != "" {
		re, err := regexp.Compile(m.SubjectRe)
		if err != nil {
			return false, err
		}
		if !re.MatchString(msg.Subject) {
			return false, nil
		}
	}
	if m.MinSize > 0 && size < m.MinSize {
		return false, nil
	}
	if m.MaxSize > 0 && size > m.MaxSize {
		return false, nil
	}
	_ = m.Direction // reserved for later routing hints
	return true, nil
}

func globMatch(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "" {
		return true
	}
	ok, err := filepath.Match(pattern, value)
	if err != nil {
		return strings.EqualFold(pattern, value)
	}
	return ok
}

func ipMatch(pattern, remote string) bool {
	pattern = strings.TrimSpace(pattern)
	remote = strings.TrimSpace(remote)
	if pattern == "" {
		return true
	}
	ip := net.ParseIP(remote)
	if ip == nil {
		// strip port if present
		host, _, err := net.SplitHostPort(remote)
		if err == nil {
			ip = net.ParseIP(host)
			remote = host
		}
	}
	if strings.Contains(pattern, "/") {
		_, n, err := net.ParseCIDR(pattern)
		if err != nil || ip == nil {
			return false
		}
		return n.Contains(ip)
	}
	return strings.EqualFold(pattern, remote)
}
