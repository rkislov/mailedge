package filter

import (
	"fmt"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/intel"
)

// BuildChain constructs the production filter chain from config.
// iocStore may be nil (intel filter will no-op until SetStore).
func BuildChain(cfg *config.Config, iocStore *intel.Store) (*Chain, error) {
	auth := NewAuthFilter()
	dnsbl := NewDNSBL()
	anti := NewAntispam()
	av := NewAV()
	sandbox := NewSandbox()
	ioc := NewIOCFilter(iocStore)
	chain := NewChain(auth, dnsbl, anti, av, sandbox, ioc)
	if err := chain.Init(cfg); err != nil {
		return nil, fmt.Errorf("filter chain: %w", err)
	}
	return chain, nil
}

// Reload re-inits filters from cfg.
func (c *Chain) Reload(cfg *config.Config) error {
	return c.Init(cfg)
}

// IOCFilter returns the intel filter from the chain, if present.
func (c *Chain) IOCFilter() *IOCFilter {
	for _, f := range c.filters {
		if i, ok := f.(*IOCFilter); ok {
			return i
		}
	}
	return nil
}
