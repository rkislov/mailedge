package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level application configuration.
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	TLS     TLSConfig     `yaml:"tls"`
	Storage StorageConfig `yaml:"storage"`
	Relay   RelayConfig   `yaml:"relay"`
	Logging LoggingConfig `yaml:"logging"`
	Policy  PolicyConfig  `yaml:"policy"`
	Filters FiltersConfig `yaml:"filters"`
}

type ServerConfig struct {
	SMTP          SMTPConfig `yaml:"smtp"`
	Web           WebConfig  `yaml:"web"`
	ControlSocket string     `yaml:"control_socket"`
	PIDFile       string     `yaml:"pid_file"`
}

type SMTPConfig struct {
	Listen          []string      `yaml:"listen"`
	Hostname        string        `yaml:"hostname"`
	MaxMessageBytes int64         `yaml:"max_message_bytes"`
	MaxRecipients   int           `yaml:"max_recipients"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	// TLS enables STARTTLS when a certificate is available (profile or files).
	TLS bool `yaml:"tls"`
	// ImplicitTLSListen — SMTPS listeners (обычно :465), TLS с первого байта.
	ImplicitTLSListen []string `yaml:"implicit_tls_listen"`
	// Legacy file paths (перекрываются tls.profiles / tls.default).
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
}

type WebConfig struct {
	Listen string `yaml:"listen"`
	TLS    bool   `yaml:"tls"`
}

// TLSConfig — управление сертификатами, УЦ и ACME.
type TLSConfig struct {
	// Dir — корень хранилища сертификатов (по умолчанию $data_dir/certs).
	Dir string `yaml:"dir"`
	// Default — имя профиля сертификата для SMTP/Web.
	Default string `yaml:"default"`
	Profiles map[string]CertProfile `yaml:"profiles"`
	CA       CAConfig               `yaml:"ca"`
	ACME     ACMEConfig             `yaml:"acme"`
}

// CertProfile описывает один именованный сертификат.
type CertProfile struct {
	// Source: file | acme | selfsigned
	Source string `yaml:"source"`
	// Cert/Key — пути к PEM (source=file). Относительные — от tls.dir.
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	// Domains — для ACME / self-signed SAN.
	Domains []string `yaml:"domains"`
}

type CAConfig struct {
	// System — включать системный trust store (по умолчанию true).
	System *bool `yaml:"system"`
	// ExtraFiles — доп. PEM-файлы УЦ.
	ExtraFiles []string `yaml:"extra_files"`
	// ExtraDir — каталог с PEM УЦ (все *.pem / *.crt).
	ExtraDir string `yaml:"extra_dir"`
}

// SystemEnabled returns whether system CAs are used (default true).
func (c CAConfig) SystemEnabled() bool {
	if c.System == nil {
		return true
	}
	return *c.System
}

type ACMEConfig struct {
	Enabled bool `yaml:"enabled"`
	// Email для регистрации ACME-аккаунта.
	Email string `yaml:"email"`
	// Directory — URL ACME directory (Let's Encrypt production по умолчанию).
	Directory string `yaml:"directory"`
	// Challenge: http-01 | tls-alpn-01
	Challenge string `yaml:"challenge"`
	// HTTPBind — слушатель для HTTP-01 (обычно :80).
	HTTPBind string `yaml:"http_bind"`
	// AgreeTOS — согласие с условиями CA.
	AgreeTOS bool `yaml:"agree_tos"`
	// Domains — домены для автоматического выпуска (если профиль не задаёт).
	Domains []string `yaml:"domains"`
}

type StorageConfig struct {
	Driver  string       `yaml:"driver"`
	DataDir string       `yaml:"data_dir"`
	SQLite  SQLiteConfig `yaml:"sqlite"`
}

type SQLiteConfig struct {
	Path        string `yaml:"path"`
	JournalMode string `yaml:"journal_mode"`
}

type RelayConfig struct {
	SmartHost      string        `yaml:"smart_host"`
	Helo           string        `yaml:"helo"`
	Workers        int           `yaml:"workers"`
	MaxAttempts    int           `yaml:"max_attempts"`
	InitialBackoff time.Duration `yaml:"initial_backoff"`
	MaxBackoff     time.Duration `yaml:"max_backoff"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type PolicyConfig struct {
	DefaultAction string       `yaml:"default_action"`
	Rules         []PolicyRule `yaml:"rules"`
}

// PolicyRule is one ordered policy decision.
type PolicyRule struct {
	ID       string         `yaml:"id"`
	Enabled  *bool          `yaml:"enabled"`
	Priority int            `yaml:"priority"`
	Action   string         `yaml:"action"` // accept, reject, quarantine, discard, tag, hold
	Reason   string         `yaml:"reason"`
	Tag      string         `yaml:"tag"`
	Match    PolicyMatch    `yaml:"match"`
}

// PolicyRuleEnabled returns whether the rule is active (default true).
func (r PolicyRule) PolicyRuleEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// PolicyMatch conditions (AND). Empty fields are ignored.
type PolicyMatch struct {
	From      string `yaml:"from"`       // exact or *glob
	To        string `yaml:"to"`         // exact or *glob (any recipient)
	RemoteIP  string `yaml:"remote_ip"`  // IP or CIDR
	Helo      string `yaml:"helo"`       // exact or *glob
	SubjectRe string `yaml:"subject_re"` // regex
	MinSize   int64  `yaml:"min_size"`
	MaxSize   int64  `yaml:"max_size"` // 0 = no max
	Direction string `yaml:"direction"` // inbound|outbound|internal (optional hint)
}

// FiltersConfig configures the filter chain.
type FiltersConfig struct {
	DNSBL    DNSBLConfig    `yaml:"dnsbl"`
	Antispam AntispamConfig `yaml:"antispam"`
	AV       AVConfig       `yaml:"av"`
	Sandbox  SandboxConfig  `yaml:"sandbox"`
	Intel    IntelConfig    `yaml:"intel"`
	DMARC    DMARCConfig    `yaml:"dmarc"`
}

type DNSBLConfig struct {
	Enabled   bool          `yaml:"enabled"`
	Zones     []DNSBLZone   `yaml:"zones"`
	Whitelist []string      `yaml:"whitelist"` // IP/CIDR
	CacheTTL  time.Duration `yaml:"cache_ttl"`
}

type DNSBLZone struct {
	Zone   string  `yaml:"zone"`
	Weight float64 `yaml:"weight"`
	Action string  `yaml:"action"` // score (default), reject, quarantine, tag
}

type AntispamConfig struct {
	Enabled         bool           `yaml:"enabled"`
	TagScore        float64        `yaml:"tag_score"`
	QuarantineScore float64        `yaml:"quarantine_score"`
	RejectScore     float64        `yaml:"reject_score"`
	Rules           []AntispamRule `yaml:"rules"`
}

type AntispamRule struct {
	ID     string  `yaml:"id"`
	Weight float64 `yaml:"weight"`
	Header string  `yaml:"header"` // empty = body
	Regex  string  `yaml:"regex"`
	URI    bool    `yaml:"uri"` // match URLs in body
}

// AVConfig is ICAP antivirus (RESPMOD).
type AVConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Servers       []ICAPServer  `yaml:"servers"`
	Timeout       time.Duration `yaml:"timeout"`
	OnUnavailable string        `yaml:"on_unavailable"` // pass | quarantine | reject
	OnInfected    string        `yaml:"on_infected"`    // reject | quarantine | tag
	MaxBytes      int64         `yaml:"max_bytes"`      // 0 = no limit (scan whole message)
}

// ICAPServer describes one ICAP endpoint.
type ICAPServer struct {
	Addr    string `yaml:"addr"`    // host:port
	Service string `yaml:"service"` // e.g. avscan
	TLS     bool   `yaml:"tls"`
}

// SandboxConfig is an HTTP sandbox / detonation adapter.
type SandboxConfig struct {
	Enabled       bool          `yaml:"enabled"`
	URL           string        `yaml:"url"`
	APIKey        string        `yaml:"api_key"`
	Timeout       time.Duration `yaml:"timeout"`
	CacheTTL      time.Duration `yaml:"cache_ttl"`
	OnUnavailable string        `yaml:"on_unavailable"` // pass | quarantine | reject
	OnMalicious   string        `yaml:"on_malicious"`   // reject | quarantine | tag
	OnSuspicious  string        `yaml:"on_suspicious"`  // tag | quarantine | pass
	MaxBytes      int64         `yaml:"max_bytes"`
	AttachmentsOnly bool        `yaml:"attachments_only"`
}

// IntelConfig is Threat Intelligence / IOC matching.
type IntelConfig struct {
	Enabled         bool              `yaml:"enabled"`
	OnHit           string            `yaml:"on_hit"` // reject | quarantine | tag
	RefreshInterval time.Duration     `yaml:"refresh_interval"`
	ThreatFox       ThreatFoxConfig   `yaml:"threatfox"`
	QFeed           QFeedConfig       `yaml:"qfeed"`
}

type ThreatFoxConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Days    int    `yaml:"days"`
}

type QFeedConfig struct {
	Enabled    bool   `yaml:"enabled"`
	URL        string `yaml:"url"`
	AuthHeader string `yaml:"auth_header"`
}

// DMARCConfig configures inbound SPF/DKIM/DMARC authentication.
type DMARCConfig struct {
	Enabled     bool   `yaml:"enabled"`
	AuthservID  string `yaml:"authserv_id"`  // Authentication-Results authserv-id
	HonorPolicy bool   `yaml:"honor_policy"` // apply DMARC p=/sp=
	AddHeader   bool   `yaml:"add_header"`   // prepend Authentication-Results
	OnFail      string `yaml:"on_fail"`      // optional override: reject|quarantine|tag
	OnTempFail  string `yaml:"on_tempfail"`  // pass|reject|quarantine
}

var envPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// ACME directory URLs.
const (
	ACMELetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	ACMELetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Load reads, expands environment variables, and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	expanded := expandEnv(string(raw))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Parse parses YAML bytes without reading a file (useful for tests).
func Parse(data []byte) (*Config, error) {
	expanded := expandEnv(string(data))
	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func expandEnv(s string) string {
	return envPattern.ReplaceAllStringFunc(s, func(match string) string {
		sub := envPattern.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		if v, ok := os.LookupEnv(sub[1]); ok {
			return v
		}
		return match
	})
}

func (c *Config) applyDefaults() {
	applyDefaults(c)
}

// ApplyDefaults fills zero-value fields with defaults (exported for admin UI).
func ApplyDefaults(c *Config) { applyDefaults(c) }

func applyDefaults(c *Config) {
	if len(c.Server.SMTP.Listen) == 0 {
		c.Server.SMTP.Listen = []string{"0.0.0.0:25"}
	}
	if c.Server.SMTP.Hostname == "" {
		c.Server.SMTP.Hostname = "localhost"
	}
	if c.Server.SMTP.MaxMessageBytes == 0 {
		c.Server.SMTP.MaxMessageBytes = 25 * 1024 * 1024
	}
	if c.Server.SMTP.MaxRecipients == 0 {
		c.Server.SMTP.MaxRecipients = 100
	}
	if c.Server.SMTP.ReadTimeout == 0 {
		c.Server.SMTP.ReadTimeout = 60 * time.Second
	}
	if c.Server.SMTP.WriteTimeout == 0 {
		c.Server.SMTP.WriteTimeout = 60 * time.Second
	}
	if c.Server.Web.Listen == "" {
		c.Server.Web.Listen = "0.0.0.0:8443"
	}
	if c.Storage.Driver == "" {
		c.Storage.Driver = "sqlite"
	}
	if c.Storage.DataDir == "" {
		c.Storage.DataDir = "./data"
	}
	if c.Storage.SQLite.Path == "" {
		c.Storage.SQLite.Path = filepath.Join(c.Storage.DataDir, "mgw.db")
	}
	if c.Storage.SQLite.JournalMode == "" {
		c.Storage.SQLite.JournalMode = "WAL"
	}
	if c.TLS.Dir == "" {
		c.TLS.Dir = filepath.Join(c.Storage.DataDir, "certs")
	}
	if c.TLS.Default == "" {
		c.TLS.Default = "default"
	}
	if c.TLS.ACME.Directory == "" {
		c.TLS.ACME.Directory = ACMELetsEncryptProduction
	}
	if c.TLS.ACME.Challenge == "" {
		c.TLS.ACME.Challenge = "http-01"
	}
	if c.TLS.ACME.HTTPBind == "" {
		c.TLS.ACME.HTTPBind = ":80"
	}
	if c.Relay.Helo == "" {
		c.Relay.Helo = c.Server.SMTP.Hostname
	}
	if c.Relay.Workers <= 0 {
		c.Relay.Workers = 2
	}
	if c.Relay.MaxAttempts <= 0 {
		c.Relay.MaxAttempts = 8
	}
	if c.Relay.InitialBackoff == 0 {
		c.Relay.InitialBackoff = 30 * time.Second
	}
	if c.Relay.MaxBackoff == 0 {
		c.Relay.MaxBackoff = time.Hour
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Policy.DefaultAction == "" {
		c.Policy.DefaultAction = "accept"
	}
	if c.Filters.DNSBL.CacheTTL == 0 {
		c.Filters.DNSBL.CacheTTL = time.Hour
	}
	if c.Filters.Antispam.TagScore == 0 && c.Filters.Antispam.QuarantineScore == 0 && c.Filters.Antispam.RejectScore == 0 {
		c.Filters.Antispam.TagScore = 5
		c.Filters.Antispam.QuarantineScore = 10
		c.Filters.Antispam.RejectScore = 15
	}
	for i := range c.Filters.DNSBL.Zones {
		z := &c.Filters.DNSBL.Zones[i]
		if z.Weight == 0 {
			z.Weight = 5
		}
		if z.Action == "" {
			z.Action = "score"
		}
	}
	if c.Filters.AV.Timeout == 0 {
		c.Filters.AV.Timeout = 15 * time.Second
	}
	if c.Filters.AV.OnUnavailable == "" {
		c.Filters.AV.OnUnavailable = "pass"
	}
	if c.Filters.AV.OnInfected == "" {
		c.Filters.AV.OnInfected = "reject"
	}
	for i := range c.Filters.AV.Servers {
		if c.Filters.AV.Servers[i].Service == "" {
			c.Filters.AV.Servers[i].Service = "avscan"
		}
	}
	if c.Filters.Sandbox.Timeout == 0 {
		c.Filters.Sandbox.Timeout = 30 * time.Second
	}
	if c.Filters.Sandbox.CacheTTL == 0 {
		c.Filters.Sandbox.CacheTTL = 24 * time.Hour
	}
	if c.Filters.Sandbox.OnUnavailable == "" {
		c.Filters.Sandbox.OnUnavailable = "pass"
	}
	if c.Filters.Sandbox.OnMalicious == "" {
		c.Filters.Sandbox.OnMalicious = "reject"
	}
	if c.Filters.Sandbox.OnSuspicious == "" {
		c.Filters.Sandbox.OnSuspicious = "tag"
	}
	if c.Filters.Sandbox.MaxBytes == 0 {
		c.Filters.Sandbox.MaxBytes = 10 << 20
	}
	if c.Filters.Intel.OnHit == "" {
		c.Filters.Intel.OnHit = "reject"
	}
	if c.Filters.Intel.RefreshInterval == 0 {
		c.Filters.Intel.RefreshInterval = time.Hour
	}
	if c.Filters.Intel.ThreatFox.URL == "" {
		c.Filters.Intel.ThreatFox.URL = "https://threatfox-api.abuse.ch/api/v1/"
	}
	if c.Filters.Intel.ThreatFox.Days <= 0 {
		c.Filters.Intel.ThreatFox.Days = 1
	}
	if c.Filters.DMARC.OnTempFail == "" {
		c.Filters.DMARC.OnTempFail = "pass"
	}
	if c.Filters.DMARC.AuthservID == "" && c.Server.SMTP.Hostname != "" {
		c.Filters.DMARC.AuthservID = c.Server.SMTP.Hostname
	}
}

// CertsDir returns the certificate store root.
func (c *Config) CertsDir() string {
	return c.TLS.Dir
}

// Validate checks required fields and sensible ranges.
func (c *Config) Validate() error {
	var errs []string
	if len(c.Server.SMTP.Listen) == 0 {
		errs = append(errs, "server.smtp.listen is required")
	}
	if c.Storage.DataDir == "" {
		errs = append(errs, "storage.data_dir is required")
	}
	switch strings.ToLower(c.Storage.Driver) {
	case "sqlite", "postgres", "memory":
	default:
		errs = append(errs, "storage.driver must be sqlite, postgres, or memory")
	}
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, "logging.level must be debug, info, warn, or error")
	}
	switch strings.ToLower(c.Logging.Format) {
	case "json", "text":
	default:
		errs = append(errs, "logging.format must be json or text")
	}
	switch strings.ToLower(c.Policy.DefaultAction) {
	case "accept", "reject", "quarantine", "discard", "hold", "tag":
	default:
		errs = append(errs, "policy.default_action must be accept, reject, quarantine, discard, hold, or tag")
	}
	for i, rule := range c.Policy.Rules {
		act := strings.ToLower(rule.Action)
		switch act {
		case "accept", "reject", "quarantine", "discard", "hold", "tag":
		default:
			errs = append(errs, fmt.Sprintf("policy.rules[%d].action invalid", i))
		}
		if rule.Match.SubjectRe != "" {
			if _, err := regexp.Compile(rule.Match.SubjectRe); err != nil {
				errs = append(errs, fmt.Sprintf("policy.rules[%d].match.subject_re: %v", i, err))
			}
		}
	}
	for i, rule := range c.Filters.Antispam.Rules {
		if rule.Regex == "" {
			errs = append(errs, fmt.Sprintf("filters.antispam.rules[%d].regex is required", i))
			continue
		}
		if _, err := regexp.Compile(rule.Regex); err != nil {
			errs = append(errs, fmt.Sprintf("filters.antispam.rules[%d].regex: %v", i, err))
		}
	}
	switch strings.ToLower(c.Filters.AV.OnUnavailable) {
	case "", "pass", "quarantine", "reject":
	default:
		errs = append(errs, "filters.av.on_unavailable must be pass, quarantine, or reject")
	}
	switch strings.ToLower(c.Filters.AV.OnInfected) {
	case "", "reject", "quarantine", "tag":
	default:
		errs = append(errs, "filters.av.on_infected must be reject, quarantine, or tag")
	}
	if c.Filters.AV.Enabled && len(c.Filters.AV.Servers) == 0 {
		errs = append(errs, "filters.av.servers is required when av is enabled")
	}
	for i, s := range c.Filters.AV.Servers {
		if strings.TrimSpace(s.Addr) == "" {
			errs = append(errs, fmt.Sprintf("filters.av.servers[%d].addr is required", i))
		}
	}
	switch strings.ToLower(c.Filters.Sandbox.OnUnavailable) {
	case "", "pass", "quarantine", "reject":
	default:
		errs = append(errs, "filters.sandbox.on_unavailable must be pass, quarantine, or reject")
	}
	switch strings.ToLower(c.Filters.Sandbox.OnMalicious) {
	case "", "reject", "quarantine", "tag":
	default:
		errs = append(errs, "filters.sandbox.on_malicious must be reject, quarantine, or tag")
	}
	if c.Filters.Sandbox.Enabled && strings.TrimSpace(c.Filters.Sandbox.URL) == "" {
		errs = append(errs, "filters.sandbox.url is required when sandbox is enabled")
	}
	switch strings.ToLower(c.Filters.Intel.OnHit) {
	case "", "reject", "quarantine", "tag":
	default:
		errs = append(errs, "filters.intel.on_hit must be reject, quarantine, or tag")
	}
	if c.Filters.Intel.QFeed.Enabled && strings.TrimSpace(c.Filters.Intel.QFeed.URL) == "" {
		errs = append(errs, "filters.intel.qfeed.url is required when qfeed is enabled")
	}
	switch strings.ToLower(c.Filters.DMARC.OnFail) {
	case "", "reject", "quarantine", "tag", "accept":
	default:
		errs = append(errs, "filters.dmarc.on_fail must be reject, quarantine, tag, or accept")
	}
	switch strings.ToLower(c.Filters.DMARC.OnTempFail) {
	case "", "pass", "reject", "quarantine":
	default:
		errs = append(errs, "filters.dmarc.on_tempfail must be pass, reject, or quarantine")
	}
	if c.Server.SMTP.MaxMessageBytes < 0 {
		errs = append(errs, "server.smtp.max_message_bytes must be >= 0")
	}
	if c.Server.SMTP.MaxRecipients < 0 {
		errs = append(errs, "server.smtp.max_recipients must be >= 0")
	}
	cert, key := c.Server.SMTP.TLSCert, c.Server.SMTP.TLSKey
	if (cert == "") != (key == "") {
		errs = append(errs, "server.smtp.tls_cert and tls_key must both be set or both empty")
	}
	chal := strings.ToLower(c.TLS.ACME.Challenge)
	if chal != "" && chal != "http-01" && chal != "tls-alpn-01" {
		errs = append(errs, "tls.acme.challenge must be http-01 or tls-alpn-01")
	}
	if c.TLS.ACME.Enabled {
		if c.TLS.ACME.Email == "" {
			errs = append(errs, "tls.acme.email is required when acme is enabled")
		}
		if !c.TLS.ACME.AgreeTOS {
			errs = append(errs, "tls.acme.agree_tos must be true when acme is enabled")
		}
	}
	for name, p := range c.TLS.Profiles {
		src := strings.ToLower(p.Source)
		if src == "" {
			src = "file"
		}
		switch src {
		case "file", "acme", "selfsigned":
		default:
			errs = append(errs, fmt.Sprintf("tls.profiles.%s.source must be file, acme, or selfsigned", name))
		}
		if src == "file" && (p.Cert == "") != (p.Key == "") {
			errs = append(errs, fmt.Sprintf("tls.profiles.%s: cert and key must both be set", name))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// SpoolDir returns the on-disk spool root.
func (c *Config) SpoolDir() string {
	return filepath.Join(c.Storage.DataDir, "spool")
}

// ExampleYAML returns the default example configuration text.
func ExampleYAML() string {
	return `server:
  smtp:
    # Порт 25 по умолчанию (нужны права root/CAP_NET_BIND_SERVICE).
    # Для локальной разработки: ["127.0.0.1:2525"]
    listen: ["0.0.0.0:25"]
    # implicit_tls_listen: ["0.0.0.0:465"]
    hostname: mail.example.com
    max_message_bytes: 26214400
    max_recipients: 100
    read_timeout: 60s
    write_timeout: 60s
    tls: true
  web:
    listen: "0.0.0.0:8443"
    tls: true

tls:
  dir: ./data/certs
  default: default
  profiles:
    default:
      # source: file | acme | selfsigned
      source: file
      cert: live/fullchain.pem
      key: live/privkey.pem
      # domains: ["mail.example.com"]
  ca:
    system: true
    # extra_files: ["/etc/mgw/ca/corp-root.pem"]
    # extra_dir: ./data/certs/ca
  acme:
    enabled: false
    email: admin@example.com
    directory: https://acme-v02.api.letsencrypt.org/directory
    # staging: https://acme-staging-v02.api.letsencrypt.org/directory
    challenge: http-01
    http_bind: ":80"
    agree_tos: false
    domains: ["mail.example.com"]

storage:
  driver: sqlite
  data_dir: ./data
  sqlite:
    path: ./data/mgw.db
    journal_mode: WAL

relay:
  smart_host: ""
  helo: mail.example.com
  workers: 2
  max_attempts: 8
  initial_backoff: 30s
  max_backoff: 1h

logging:
  level: info
  format: json

policy:
  default_action: accept
  rules: []

filters:
  dmarc:
    enabled: true
    authserv_id: ""
    honor_policy: true
    add_header: true
    on_fail: ""
    on_tempfail: pass
  dnsbl:
    enabled: false
    cache_ttl: 1h
    whitelist:
      - 127.0.0.0/8
      - 10.0.0.0/8
      - 192.168.0.0/16
    zones:
      # - zone: zen.spamhaus.org
      #   weight: 10
      #   action: reject
  antispam:
    enabled: true
    tag_score: 5
    quarantine_score: 10
    reject_score: 15
    rules:
      - id: subject_pharma
        weight: 5
        header: Subject
        regex: "(?i)\\b(viagra|cialis|levitra)\\b"
      - id: body_casino
        weight: 3
        regex: "(?i)\\b(online casino|poker freeroll)\\b"
  av:
    enabled: false
    timeout: 15s
    on_unavailable: pass
    on_infected: reject
    servers: []
  sandbox:
    enabled: false
    url: ""
    timeout: 30s
    cache_ttl: 24h
    on_unavailable: pass
    on_malicious: reject
    on_suspicious: tag
    max_bytes: 10485760
  intel:
    enabled: false
    on_hit: reject
    refresh_interval: 1h
    threatfox:
      enabled: false
      days: 1
    qfeed:
      enabled: false
      url: ""
`
}
