package filter

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/mailmsg"
)

// DNSBL checks the remote IP against configured DNS blackhole lists.
type DNSBL struct {
	mu        sync.RWMutex
	cfg       config.DNSBLConfig
	whitelist []*net.IPNet
	cache     map[string]dnsblCacheEntry
	lookup    func(ctx context.Context, name string) ([]net.IP, error)
	now       func() time.Time
}

type dnsblCacheEntry struct {
	listed bool
	zone   string
	until  time.Time
}

// NewDNSBL creates a DNSBL filter.
func NewDNSBL() *DNSBL {
	return &DNSBL{
		cache: make(map[string]dnsblCacheEntry),
		lookup: func(ctx context.Context, name string) ([]net.IP, error) {
			var r net.Resolver
			return r.LookupIP(ctx, "ip4", name)
		},
		now: time.Now,
	}
}

func (d *DNSBL) Name() string { return "dnsbl" }

func (d *DNSBL) Init(cfg *config.Config) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if cfg == nil {
		d.cfg = config.DNSBLConfig{}
		return nil
	}
	d.cfg = cfg.Filters.DNSBL
	d.whitelist = nil
	for _, cidr := range d.cfg.Whitelist {
		_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			ip := net.ParseIP(strings.TrimSpace(cidr))
			if ip == nil {
				return fmt.Errorf("dnsbl whitelist %q: %w", cidr, err)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			_, n, err = net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), bits))
			if err != nil {
				return err
			}
		}
		d.whitelist = append(d.whitelist, n)
	}
	if d.cfg.CacheTTL <= 0 {
		d.cfg.CacheTTL = time.Hour
	}
	return nil
}

func (d *DNSBL) Close() error { return nil }

// SetLookup overrides the DNS resolver (tests).
func (d *DNSBL) SetLookup(fn func(ctx context.Context, name string) ([]net.IP, error)) {
	d.mu.Lock()
	d.lookup = fn
	d.mu.Unlock()
}

func (d *DNSBL) Process(ctx context.Context, msg *mailmsg.Message, _ []byte) (*mailmsg.Result, error) {
	d.mu.RLock()
	cfg := d.cfg
	wl := d.whitelist
	d.mu.RUnlock()
	if !cfg.Enabled || len(cfg.Zones) == 0 || msg == nil {
		return &mailmsg.Result{Action: "accept"}, nil
	}
	ip := parseRemoteIP(msg.RemoteIP)
	if ip == nil || ip.To4() == nil {
		return &mailmsg.Result{Action: "accept", Reason: "dnsbl: no ipv4"}, nil
	}
	for _, n := range wl {
		if n.Contains(ip) {
			return &mailmsg.Result{Action: "accept", Reason: "dnsbl: whitelisted", Tags: []string{"dnsbl:whitelist"}}, nil
		}
	}

	var score float64
	var hits []string
	var hardAction string
	var hardReason string

	for _, zone := range cfg.Zones {
		zone.Zone = strings.TrimSuffix(strings.TrimSpace(zone.Zone), ".")
		if zone.Zone == "" {
			continue
		}
		listed, err := d.isListed(ctx, ip, zone.Zone, cfg.CacheTTL)
		if err != nil {
			// soft-fail on DNS errors
			continue
		}
		if !listed {
			continue
		}
		hits = append(hits, zone.Zone)
		score += zone.Weight
		act := strings.ToLower(zone.Action)
		if act == "" {
			act = "score"
		}
		if act != "score" && hardAction == "" {
			hardAction = act
			hardReason = "dnsbl hit: " + zone.Zone
		}
	}

	if len(hits) == 0 {
		return &mailmsg.Result{Action: "accept"}, nil
	}

	res := &mailmsg.Result{
		Score:  score,
		Tags:   []string{"dnsbl:" + strings.Join(hits, ",")},
		Reason: "dnsbl: " + strings.Join(hits, ","),
		Details: map[string]string{
			"zones": strings.Join(hits, ","),
		},
		Action: "tag",
	}
	if hardAction != "" {
		res.Action = hardAction
		res.Reason = hardReason
	}
	return res, nil
}

func (d *DNSBL) isListed(ctx context.Context, ip net.IP, zone string, ttl time.Duration) (bool, error) {
	key := ip.String() + "|" + zone
	d.mu.RLock()
	if e, ok := d.cache[key]; ok && d.now().Before(e.until) {
		d.mu.RUnlock()
		return e.listed, nil
	}
	d.mu.RUnlock()

	qname := reverseIPv4(ip) + "." + zone
	ips, err := d.lookup(ctx, qname)
	listed := err == nil && len(ips) > 0
	if err != nil {
		// NXDOMAIN etc. → not listed
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			listed = false
			err = nil
		} else if strings.Contains(strings.ToLower(err.Error()), "no such host") {
			listed = false
			err = nil
		}
	}

	d.mu.Lock()
	d.cache[key] = dnsblCacheEntry{listed: listed, zone: zone, until: d.now().Add(ttl)}
	d.mu.Unlock()
	return listed, err
}

func reverseIPv4(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
}

func parseRemoteIP(remote string) net.IP {
	remote = strings.TrimSpace(remote)
	if ip := net.ParseIP(remote); ip != nil {
		return ip
	}
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		return net.ParseIP(host)
	}
	return nil
}
