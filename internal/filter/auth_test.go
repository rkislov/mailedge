package filter_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/filter"
	"github.com/rkislov/mailedge/internal/mailmsg"
)

func TestAuthFilterDMARCReject(t *testing.T) {
	a := filter.NewAuthFilter()
	cfg := &config.Config{
		Server: config.ServerConfig{SMTP: config.SMTPConfig{Hostname: "mgw.test"}},
		Filters: config.FiltersConfig{DMARC: config.DMARCConfig{
			Enabled:     true,
			HonorPolicy: true,
			AddHeader:   true,
			AuthservID:  "mgw.test",
		}},
	}
	if err := a.Init(cfg); err != nil {
		t.Fatal(err)
	}

	a.LookupTXT = func(name string) ([]string, error) {
		switch {
		case strings.HasPrefix(name, "_dmarc."):
			return []string{"v=DMARC1; p=reject; adkim=r; aspf=r"}, nil
		case name == "evil.example":
			return []string{"v=spf1 -all"}, nil
		default:
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
	}
	a.LookupIP = func(host string) ([]net.IP, error) { return nil, nil }
	a.LookupMX = func(name string) ([]*net.MX, error) { return nil, nil }
	a.VerifyDKIM = func(r io.Reader) ([]*dkim.Verification, error) {
		_, _ = io.Copy(io.Discard, r)
		return nil, nil
	}

	raw := []byte("From: spoof@evil.example\r\nSubject: test\r\n\r\nbody\r\n")
	msg := &mailmsg.Message{
		From:     "spoof@evil.example",
		RemoteIP: "8.8.8.8",
		Helo:     "mail.evil.example",
	}
	res, err := a.Process(context.Background(), msg, raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "reject" {
		t.Fatalf("action=%s details=%v", res.Action, res.Details)
	}
	if res.Details["dmarc"] != "fail" {
		t.Fatalf("dmarc=%s", res.Details["dmarc"])
	}
	if len(res.PrependHeaders) == 0 || !strings.Contains(res.PrependHeaders[0], "Authentication-Results:") {
		t.Fatalf("missing auth results: %v", res.PrependHeaders)
	}
	if !strings.Contains(res.PrependHeaders[0], "dmarc=fail") {
		t.Fatalf("header=%s", res.PrependHeaders[0])
	}
}

func TestAuthFilterSPFPassAligned(t *testing.T) {
	a := filter.NewAuthFilter()
	if err := a.Init(&config.Config{Filters: config.FiltersConfig{DMARC: config.DMARCConfig{
		Enabled: true, HonorPolicy: true, AddHeader: true, AuthservID: "mgw.test",
	}}}); err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("203.0.113.10")
	a.LookupTXT = func(name string) ([]string, error) {
		switch {
		case name == "good.example":
			return []string{"v=spf1 ip4:203.0.113.10 -all"}, nil
		case strings.HasPrefix(name, "_dmarc."):
			return []string{"v=DMARC1; p=reject"}, nil
		default:
			return nil, fmt.Errorf("unexpected TXT %s", name)
		}
	}
	a.VerifyDKIM = func(r io.Reader) ([]*dkim.Verification, error) {
		_, _ = io.Copy(io.Discard, r)
		return nil, nil
	}

	raw := []byte("From: alice@good.example\r\n\r\nhi\r\n")
	res, err := a.Process(context.Background(), &mailmsg.Message{
		From: "alice@good.example", RemoteIP: ip.String(), Helo: "mail.good.example",
	}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "accept" {
		t.Fatalf("action=%s %+v", res.Action, res.Details)
	}
	if res.Details["dmarc"] != "pass" || res.Details["spf"] != "pass" {
		t.Fatalf("details=%v", res.Details)
	}
}

func TestAuthFilterOnFailOverride(t *testing.T) {
	a := filter.NewAuthFilter()
	if err := a.Init(&config.Config{Filters: config.FiltersConfig{DMARC: config.DMARCConfig{
		Enabled: true, HonorPolicy: false, OnFail: "quarantine", AddHeader: false,
	}}}); err != nil {
		t.Fatal(err)
	}
	a.LookupTXT = func(name string) ([]string, error) {
		if strings.HasPrefix(name, "_dmarc.") {
			return []string{"v=DMARC1; p=reject"}, nil
		}
		return []string{"v=spf1 -all"}, nil
	}
	a.VerifyDKIM = func(r io.Reader) ([]*dkim.Verification, error) {
		_, _ = io.Copy(io.Discard, r)
		return nil, nil
	}
	res, err := a.Process(context.Background(), &mailmsg.Message{
		From: "x@bad.example", RemoteIP: "1.2.3.4",
	}, []byte("From: x@bad.example\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "quarantine" {
		t.Fatalf("want quarantine got %s", res.Action)
	}
	if len(res.PrependHeaders) != 0 {
		t.Fatalf("unexpected headers %v", res.PrependHeaders)
	}
}

func TestPrependHeaders(t *testing.T) {
	out := filter.PrependHeaders([]byte("From: a\r\n\r\nb\r\n"), []string{"X-Test: 1"})
	if !strings.HasPrefix(string(out), "X-Test: 1\r\nFrom:") {
		t.Fatalf("%q", out)
	}
}
