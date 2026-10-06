package filter

import (
	"fmt"

	"github.com/rkislov/mailedge/internal/config"
)

// BuildChain constructs the production filter chain from config.
func BuildChain(cfg *config.Config) (*Chain, error) {
	dnsbl := NewDNSBL()
	anti := NewAntispam()
	chain := NewChain(dnsbl, anti)
	if err := chain.Init(cfg); err != nil {
		return nil, fmt.Errorf("filter chain: %w", err)
	}
	return chain, nil
}

// Reload re-inits filters from cfg.
func (c *Chain) Reload(cfg *config.Config) error {
	return c.Init(cfg)
}
