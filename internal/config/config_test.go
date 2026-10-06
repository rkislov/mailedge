package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
server:
  smtp:
    listen: ["127.0.0.1:2525"]
    hostname: test.local
storage:
  data_dir: ` + dir + `/data
logging:
  level: debug
  format: text
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.SMTP.Hostname != "test.local" {
		t.Errorf("hostname = %q", cfg.Server.SMTP.Hostname)
	}
	if cfg.Relay.Workers != 2 {
		t.Errorf("default workers = %d", cfg.Relay.Workers)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("server: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestValidateBadDriver(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	cfg.Storage.Driver = "mysql"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestExpandEnv(t *testing.T) {
	t.Setenv("MGW_TEST_HOST", "relay.example")
	data := []byte(`
server:
  smtp:
    listen: ["127.0.0.1:2525"]
storage:
  data_dir: ./data
relay:
  smart_host: "${MGW_TEST_HOST}:25"
logging:
  level: info
  format: json
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Relay.SmartHost != "relay.example:25" {
		t.Errorf("smart_host = %q", cfg.Relay.SmartHost)
	}
}
