package intel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/storage/sqlite"
)

type feedTransport func(*http.Request) (*http.Response, error)

func (f feedTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSecurityFeedSubscription(t *testing.T) {
	t.Setenv("MGW_SECURITY_FEED_API_KEY", "test-subscription")
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "mgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/feeds/v1/iocs.json" || r.Header.Get("X-Api-Key") != "test-subscription" {
			http.Error(w, "invalid feed request", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `[{"type":"domain","value":"phishing.example","source":"threatfox","threat":"phishing"}]`)
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	feeder := NewFeeder(NewStore(db.SQL()), func() config.IntelConfig {
		return config.IntelConfig{
			Enabled: true,
			QFeed:   config.QFeedConfig{Enabled: true, URL: config.SecurityFeedURL},
		}
	}, nil)
	feeder.client.Transport = feedTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != config.SecurityFeedURL {
			t.Errorf("unexpected upstream: %s", req.URL)
		}
		local := req.Clone(req.Context())
		local.URL.Scheme, local.URL.Host = target.Scheme, target.Host
		return server.Client().Transport.RoundTrip(local)
	})
	if count, err := feeder.Refresh(context.Background()); err != nil || count != 1 {
		t.Fatalf("refresh count=%d err=%v", count, err)
	}
}
