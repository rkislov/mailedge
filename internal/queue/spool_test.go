package queue

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rkislov/mailedge/internal/mailmsg"
)

func TestEnqueueClaimComplete(t *testing.T) {
	dir := t.TempDir()
	sp, err := New(dir, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatal(err)
	}

	msg := &mailmsg.Message{From: "a@example.com", To: []string{"b@example.com"}}
	data := []byte("From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nbody\r\n")
	if err := sp.Enqueue(msg, data); err != nil {
		t.Fatal(err)
	}

	claimed, err := sp.ClaimReady(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 {
		t.Fatalf("claimed %d", len(claimed))
	}
	if claimed[0].State != mailmsg.StateActive {
		t.Fatalf("state = %s", claimed[0].State)
	}

	raw, err := sp.ReadData(claimed[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(data) {
		t.Fatal("data mismatch")
	}

	if err := sp.Complete(claimed[0]); err != nil {
		t.Fatal(err)
	}
	stats, err := sp.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats["active"] != 0 || stats["incoming"] != 0 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestDeferAndRecover(t *testing.T) {
	dir := t.TempDir()
	sp, err := New(dir, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	msg := &mailmsg.Message{From: "a@ex.com", To: []string{"b@ex.com"}}
	if err := sp.Enqueue(msg, []byte("x")); err != nil {
		t.Fatal(err)
	}
	claimed, err := sp.ClaimReady(1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v len=%d", err, len(claimed))
	}
	if err := sp.Defer(claimed[0], "temp fail", time.Hour, time.Hour, 8); err != nil {
		t.Fatal(err)
	}
	// Not due yet.
	again, err := sp.ClaimReady(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("expected 0 due, got %d", len(again))
	}

	// Simulate crash: put a message in active manually via claim then recover.
	msg2 := &mailmsg.Message{From: "c@ex.com", To: []string{"d@ex.com"}}
	if err := sp.Enqueue(msg2, []byte("y")); err != nil {
		t.Fatal(err)
	}
	claimed2, _ := sp.ClaimReady(1)
	if len(claimed2) != 1 {
		t.Fatal("expected claim")
	}
	n, err := sp.RecoverActive()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("recovered %d", n)
	}
	// Force next_attempt by rewriting meta.
	deferred := filepath.Join(sp.Root(), "deferred", claimed2[0].ID+".json")
	m, err := readMeta(deferred)
	if err != nil {
		t.Fatal(err)
	}
	m.NextAttempt = time.Now().UTC().Add(-time.Second)
	if err := writeMeta(deferred, m); err != nil {
		t.Fatal(err)
	}
	ready, err := sp.ClaimReady(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ready) != 1 {
		t.Fatalf("expected recovered message ready, got %d", len(ready))
	}
}
