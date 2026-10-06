package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Save writes cfg as YAML to path (atomic replace).
func Save(path string, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	b, err := Marshal(cfg)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Marshal encodes config to YAML bytes.
func Marshal(cfg *Config) ([]byte, error) {
	return yamlMarshal(cfg)
}

// ApplySettings updates operational fields from a settings form payload.
type SettingsPatch struct {
	SMTPListen          string
	ImplicitTLSListen   string
	Hostname            string
	MaxMessageBytes     int64
	MaxRecipients       int
	SMTPTLS            bool
	WebListen           string
	WebTLS              bool
	SmartHost           string
	RelayHelo           string
	RelayWorkers        int
	LogLevel            string
	LogFormat           string
	DefaultAction       string
	ACMEEnabled         bool
	ACMEEmail           string
	ACMEHTTPBind        string
	ACMEAgreeTOS        bool
	ACMEDomains         string
	ACMEDirectory       string
	ACMEChallenge       string
}

// ApplyPatch mutates cfg with patch values (non-empty / provided).
func (c *Config) ApplyPatch(p SettingsPatch) {
	if strings.TrimSpace(p.SMTPListen) != "" {
		c.Server.SMTP.Listen = splitCSV(p.SMTPListen)
	}
	c.Server.SMTP.ImplicitTLSListen = splitCSV(p.ImplicitTLSListen)
	if p.Hostname != "" {
		c.Server.SMTP.Hostname = p.Hostname
	}
	if p.MaxMessageBytes > 0 {
		c.Server.SMTP.MaxMessageBytes = p.MaxMessageBytes
	}
	if p.MaxRecipients > 0 {
		c.Server.SMTP.MaxRecipients = p.MaxRecipients
	}
	c.Server.SMTP.TLS = p.SMTPTLS
	if p.WebListen != "" {
		c.Server.Web.Listen = p.WebListen
	}
	c.Server.Web.TLS = p.WebTLS
	c.Relay.SmartHost = strings.TrimSpace(p.SmartHost)
	if p.RelayHelo != "" {
		c.Relay.Helo = p.RelayHelo
	}
	if p.RelayWorkers > 0 {
		c.Relay.Workers = p.RelayWorkers
	}
	if p.LogLevel != "" {
		c.Logging.Level = p.LogLevel
	}
	if p.LogFormat != "" {
		c.Logging.Format = p.LogFormat
	}
	if p.DefaultAction != "" {
		c.Policy.DefaultAction = p.DefaultAction
	}
	c.TLS.ACME.Enabled = p.ACMEEnabled
	if p.ACMEEmail != "" {
		c.TLS.ACME.Email = p.ACMEEmail
	}
	if p.ACMEHTTPBind != "" {
		c.TLS.ACME.HTTPBind = p.ACMEHTTPBind
	}
	c.TLS.ACME.AgreeTOS = p.ACMEAgreeTOS
	if p.ACMEDomains != "" {
		c.TLS.ACME.Domains = splitCSV(p.ACMEDomains)
	}
	if p.ACMEDirectory != "" {
		c.TLS.ACME.Directory = p.ACMEDirectory
	}
	if p.ACMEChallenge != "" {
		c.TLS.ACME.Challenge = p.ACMEChallenge
	}
}

// NeedsRestart reports whether patch changes require process restart.
func NeedsRestart(old, neu *Config) bool {
	if joinCSV(old.Server.SMTP.Listen) != joinCSV(neu.Server.SMTP.Listen) {
		return true
	}
	if joinCSV(old.Server.SMTP.ImplicitTLSListen) != joinCSV(neu.Server.SMTP.ImplicitTLSListen) {
		return true
	}
	if old.Server.Web.Listen != neu.Server.Web.Listen {
		return true
	}
	if old.Server.Web.TLS != neu.Server.Web.TLS {
		return true
	}
	if old.TLS.ACME.HTTPBind != neu.TLS.ACME.HTTPBind {
		return true
	}
	if old.TLS.ACME.Enabled != neu.TLS.ACME.Enabled {
		return true
	}
	return false
}

func splitCSV(s string) []string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinCSV(ss []string) string {
	return strings.Join(ss, ", ")
}

func yamlMarshal(v any) ([]byte, error) {
	return marshalYAML(v)
}
