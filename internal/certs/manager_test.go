package certs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rkislov/mailedge/internal/config"
)

func TestImportAndList(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Parse([]byte(`
server:
  smtp:
    listen: ["127.0.0.1:2525"]
    hostname: mail.test.local
storage:
  data_dir: ` + dir + `
tls:
  dir: ` + filepath.Join(dir, "certs") + `
`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := GenerateSelfSigned([]string{"mail.test.local"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Import(certPEM, keyPEM, "live"); err != nil {
		t.Fatal(err)
	}
	list, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Fatal("expected certs")
	}
	if m.Certificate() == nil {
		t.Fatal("expected active certificate")
	}
	if m.ServerTLSConfig() == nil {
		t.Fatal("expected tls config")
	}
}

func TestAddCA(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Parse([]byte(`
server:
  smtp:
    listen: ["127.0.0.1:2525"]
storage:
  data_dir: ` + dir + `
tls:
  dir: ` + filepath.Join(dir, "certs") + `
  ca:
    system: false
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.CA.SystemEnabled() {
		t.Fatal("expected system CA disabled")
	}
	m, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := GenerateSelfSigned([]string{"ca.test"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(src, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.AddCA(src, "corp-root.pem"); err != nil {
		t.Fatal(err)
	}
	names, err := m.ListCA()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "corp-root.pem" {
		t.Fatalf("ca list = %v", names)
	}
}

func TestDefaultListenPort25(t *testing.T) {
	cfg, err := config.Parse([]byte(`
storage:
  data_dir: ./data
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Server.SMTP.Listen) != 1 || cfg.Server.SMTP.Listen[0] != "0.0.0.0:25" {
		t.Fatalf("listen = %v", cfg.Server.SMTP.Listen)
	}
}
