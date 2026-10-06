package filter_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/filter"
	"github.com/rkislov/mailedge/internal/filter/icap"
	"github.com/rkislov/mailedge/internal/mailmsg"
)

func TestAVInfectedViaICAP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go mockICAPInfected(t, ln)

	av := filter.NewAV()
	cfg := &config.Config{Filters: config.FiltersConfig{AV: config.AVConfig{
		Enabled:    true,
		Timeout:    3 * time.Second,
		OnInfected: "reject",
		Servers:    []config.ICAPServer{{Addr: ln.Addr().String(), Service: "avscan"}},
	}}}
	if err := av.Init(cfg); err != nil {
		t.Fatal(err)
	}
	res, err := av.Process(context.Background(), &mailmsg.Message{ID: "1"}, []byte("EICAR"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "reject" || !strings.Contains(res.Reason, "Eicar") {
		t.Fatalf("got %+v", res)
	}
}

func TestSandboxMalicious(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(map[string]any{"verdict": "malicious", "threat": "trojan.test"})
	}))
	defer srv.Close()

	sb := filter.NewSandbox()
	cfg := &config.Config{Filters: config.FiltersConfig{Sandbox: config.SandboxConfig{
		Enabled:     true,
		URL:         srv.URL,
		Timeout:     3 * time.Second,
		CacheTTL:    time.Hour,
		OnMalicious: "quarantine",
		MaxBytes:    1 << 20,
	}}}
	if err := sb.Init(cfg); err != nil {
		t.Fatal(err)
	}
	res, err := sb.Process(context.Background(), &mailmsg.Message{}, []byte("Subject: x\r\n\r\nbody"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "quarantine" {
		t.Fatalf("got %+v", res)
	}
	// cache hit
	res2, err := sb.Process(context.Background(), &mailmsg.Message{}, []byte("Subject: x\r\n\r\nbody"))
	if err != nil || res2.Action != "quarantine" {
		t.Fatalf("cache: %+v %v", res2, err)
	}
}

func mockICAPInfected(t *testing.T, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	buf := make([]byte, 64<<10)
	n, _ := conn.Read(buf)
	_ = n
	resp := "ICAP/1.0 200 OK\r\n" +
		"ISTag: \"t\"\r\n" +
		"X-Infection-Found: Type=0; Resolution=2; Threat=Eicar-Test-Signature;\r\n" +
		"Encapsulated: null-body=0\r\n\r\n"
	_, _ = conn.Write([]byte(resp))
}

// ensure icap package linked
var _ = icap.Client{}
