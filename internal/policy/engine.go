package policy

import (
	"context"
	"strings"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/mailmsg"
)

// Engine evaluates mail against policies. Stage 1: default action only.
type Engine struct {
	defaultAction string
}

// New creates a policy engine from config.
func New(cfg *config.Config) *Engine {
	action := "accept"
	if cfg != nil && cfg.Policy.DefaultAction != "" {
		action = strings.ToLower(cfg.Policy.DefaultAction)
	}
	return &Engine{defaultAction: action}
}

// Evaluate returns the policy decision for a message.
func (e *Engine) Evaluate(_ context.Context, _ *mailmsg.Message, _ []byte) (*mailmsg.Result, error) {
	return &mailmsg.Result{
		Action: e.defaultAction,
		Reason: "default policy",
	}, nil
}
