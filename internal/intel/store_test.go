package intel_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/filter"
	"github.com/rkislov/mailedge/internal/intel"
	"github.com/rkislov/mailedge/internal/mailmsg"
	"github.com/rkislov/mailedge/internal/storage/sqlite"
)

func TestStoreAndFilter(t *testing.T) {
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := intel.NewStore(db.SQL())
	ctx := context.Background()
	if _, err := store.Upsert(ctx, intel.IOC{Type: "ip", Value: "203.0.113.9", Threat: "test-bot", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert(ctx, intel.IOC{Type: "domain", Value: "evil.example", Threat: "phish", Source: "manual"}); err != nil {
		t.Fatal(err)
	}

	f := filter.NewIOCFilter(store)
	cfg := &config.Config{Filters: config.FiltersConfig{Intel: config.IntelConfig{Enabled: true, OnHit: "quarantine"}}}
	if err := f.Init(cfg); err != nil {
		t.Fatal(err)
	}
	res, err := f.Process(ctx, &mailmsg.Message{RemoteIP: "203.0.113.9", From: "a@x.test"}, []byte("Subject: hi\r\n\r\nhello"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "quarantine" {
		t.Fatalf("want quarantine got %+v", res)
	}

	res, err = f.Process(ctx, &mailmsg.Message{From: "user@evil.example"}, []byte("Subject: x\r\n\r\nsee https://evil.example/pay"))
	if err != nil || res.Action != "quarantine" {
		t.Fatalf("domain hit: %+v %v", res, err)
	}
}

func TestQFeedPull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"type":"ip","value":"198.51.100.1","threat":"c2"}]`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := intel.NewStore(db.SQL())
	feeder := intel.NewFeeder(store, func() config.IntelConfig {
		return config.IntelConfig{
			Enabled: true,
			QFeed:   config.QFeedConfig{Enabled: true, URL: srv.URL},
		}
	}, nil)
	n, err := feeder.Refresh(context.Background())
	if err != nil || n < 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	hit, err := store.Get(context.Background(), "ip", "198.51.100.1")
	if err != nil || hit == nil {
		t.Fatalf("miss: %v %v", hit, err)
	}
}
