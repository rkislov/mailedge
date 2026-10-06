package filter

import (
	"context"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/mailmsg"
)

// Filter is the common interface for all mail filters.
type Filter interface {
	Name() string
	Init(cfg *config.Config) error
	Process(ctx context.Context, msg *mailmsg.Message, data []byte) (*mailmsg.Result, error)
	Close() error
}

// Result aliases mailmsg.Result for package-local clarity.
type Result = mailmsg.Result

// Noop is a pass-through filter used in Stage 1.
type Noop struct{}

func (n *Noop) Name() string                         { return "noop" }
func (n *Noop) Init(_ *config.Config) error          { return nil }
func (n *Noop) Close() error                         { return nil }
func (n *Noop) Process(_ context.Context, _ *mailmsg.Message, _ []byte) (*mailmsg.Result, error) {
	return &mailmsg.Result{Action: "accept"}, nil
}

// Chain runs filters in order until a non-accept action or error.
type Chain struct {
	filters []Filter
}

// NewChain builds a filter chain.
func NewChain(filters ...Filter) *Chain {
	return &Chain{filters: filters}
}

// Init initializes all filters.
func (c *Chain) Init(cfg *config.Config) error {
	for _, f := range c.filters {
		if err := f.Init(cfg); err != nil {
			return err
		}
	}
	return nil
}

// Process runs the chain.
func (c *Chain) Process(ctx context.Context, msg *mailmsg.Message, data []byte) (*mailmsg.Result, error) {
	final := &mailmsg.Result{Action: "accept"}
	for _, f := range c.filters {
		res, err := f.Process(ctx, msg, data)
		if err != nil {
			return nil, err
		}
		if res == nil {
			continue
		}
		if len(res.Tags) > 0 {
			final.Tags = append(final.Tags, res.Tags...)
		}
		if res.Action != "" && res.Action != "accept" && res.Action != "tag" {
			return res, nil
		}
		if res.Action == "tag" {
			final.Action = "accept"
		}
	}
	return final, nil
}

// Close closes all filters.
func (c *Chain) Close() error {
	var first error
	for _, f := range c.filters {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
