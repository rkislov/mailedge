package filter_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/filter"
	"github.com/rkislov/mailedge/internal/mailmsg"
)

func TestAntispamScoring(t *testing.T) {
	cfg := &config.Config{Filters: config.FiltersConfig{Antispam: config.AntispamConfig{
		Enabled:         true,
		TagScore:        3,
		QuarantineScore: 8,
		RejectScore:     12,
		Rules: []config.AntispamRule{
			{ID: "viagra", Weight: 5, Header: "Subject", Regex: `(?i)viagra`},
			{ID: "casino", Weight: 4, Regex: `(?i)casino`},
		},
	}}}
	a := filter.NewAntispam()
	if err := a.Init(cfg); err != nil {
		t.Fatal(err)
	}
	raw := []byte("Subject: Buy Viagra cheap\r\n\r\nVisit online casino today\r\n")
	res, err := a.Process(context.Background(), &mailmsg.Message{Subject: "Buy Viagra cheap"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Score < 9 {
		t.Fatalf("score=%v want >=9", res.Score)
	}
	if res.Action != "quarantine" {
		t.Fatalf("action=%s want quarantine", res.Action)
	}
}

func TestDNSBLWhitelistAndHit(t *testing.T) {
	d := filter.NewDNSBL()
	cfg := &config.Config{Filters: config.FiltersConfig{DNSBL: config.DNSBLConfig{
		Enabled:   true,
		CacheTTL:  time.Minute,
		Whitelist: []string{"127.0.0.0/8"},
		Zones:     []config.DNSBLZone{{Zone: "test.blacklist", Weight: 10, Action: "reject"}},
	}}}
	if err := d.Init(cfg); err != nil {
		t.Fatal(err)
	}
	// inject lookup via unexported field — use package-level helper by testing whitelist path
	res, err := d.Process(context.Background(), &mailmsg.Message{RemoteIP: "127.0.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "accept" {
		t.Fatalf("whitelist failed: %+v", res)
	}

	// listed IP via custom resolver: set through Init then replace by exporting SetLookup for tests
	d.SetLookup(func(ctx context.Context, name string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.2")}, nil
	})
	res, err = d.Process(context.Background(), &mailmsg.Message{RemoteIP: "8.8.8.8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "reject" {
		t.Fatalf("want reject got %+v", res)
	}
}
