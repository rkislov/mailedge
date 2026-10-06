package admin

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/mailedge/internal/auth"
	"github.com/rkislov/mailedge/internal/certs"
	"github.com/rkislov/mailedge/internal/config"
	dkimkeys "github.com/rkislov/mailedge/internal/dkim"
	"github.com/rkislov/mailedge/internal/domains"
	"github.com/rkislov/mailedge/internal/filter"
	"github.com/rkislov/mailedge/internal/metrics"
	"github.com/rkislov/mailedge/internal/policy"
	"github.com/rkislov/mailedge/internal/quarantine"
	"github.com/rkislov/mailedge/internal/queue"
	"github.com/rkislov/mailedge/internal/version"
)

//go:embed templates/*.html
var templatesFS embed.FS

const (
	sessionCookie = "mgw_session"
	sessionTTL    = 12 * time.Hour
)

// Deps are runtime dependencies for the admin UI.
type Deps struct {
	CfgPath    string
	Cfg        *config.Config
	CfgMu      *sync.RWMutex
	Auth       *auth.Service
	Certs      *certs.Manager
	Domains    *domains.Store
	DKIM       *dkimkeys.Manager
	Spool      *queue.Spool
	Metrics    *metrics.Registry
	History    *metrics.History
	Policy     *policy.Engine
	Filters    *filter.Chain
	Quarantine *quarantine.Store
	Log        *slog.Logger
	Started    time.Time
}

// Handler serves /admin/* routes.
type Handler struct {
	deps Deps
	tmpl *template.Template
}

func New(deps Deps) (*Handler, error) {
	funcMap := template.FuncMap{
		"join": strings.Join,
		"yesno": func(b bool) string {
			if b {
				return "да"
			}
			return "нет"
		},
		"safe": func(s string) template.HTML { return template.HTML(s) },
	}
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Started.IsZero() {
		deps.Started = time.Now().UTC()
	}
	return &Handler{deps: deps, tmpl: tmpl}, nil
}

// Mount registers admin routes under mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/setup", h.setup)
	mux.HandleFunc("/login", h.login)
	mux.HandleFunc("/logout", h.logout)
	mux.HandleFunc("/admin", h.requireAuth(h.dashboard))
	mux.HandleFunc("/admin/", h.requireAuth(h.adminRouter))
}

func (h *Handler) adminRouter(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/admin")
	if p == "" || p == "/" {
		h.dashboard(w, r)
		return
	}
	switch {
	case p == "/api/live" || strings.HasPrefix(p, "/api/live"):
		h.liveAPI(w, r)
	case p == "/settings" || strings.HasPrefix(p, "/settings"):
		h.settings(w, r)
	case p == "/certs" || strings.HasPrefix(p, "/certs"):
		h.certsPage(w, r)
	case p == "/domains" || strings.HasPrefix(p, "/domains"):
		h.domainsPage(w, r)
	case p == "/dkim" || strings.HasPrefix(p, "/dkim"):
		h.dkimPage(w, r)
	case p == "/policies" || strings.HasPrefix(p, "/policies"):
		h.policiesPage(w, r)
	case p == "/filters" || strings.HasPrefix(p, "/filters"):
		h.filtersPage(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) liveAPI(w http.ResponseWriter, r *http.Request) {
	if h.deps.History == nil {
		http.Error(w, `{"error":"no history"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(h.deps.History.LivePayload())
}

type pageData struct {
	Title      string
	Active     string
	User       string
	CSRF       string
	Flash      string
	Error      string
	NeedsSetup bool
	Version    string
	Uptime     string
	Hostname   string
	Metrics    map[string]int64
	Queue      map[string]int
	Cfg        *config.Config
	Restart    bool
	Certs      []certs.Info
	CAList     []string
	ACME       certs.ACMEStatus
	Domains    []domains.Domain
	Routes     []domains.Route
	Aliases    []domains.Alias
	DKIMKeys   []dkimkeys.Key
	DNSHints   map[int64]string
}

func (h *Handler) base(r *http.Request, title, active string) pageData {
	h.deps.CfgMu.RLock()
	cfg := h.deps.Cfg
	h.deps.CfgMu.RUnlock()
	pd := pageData{
		Title:    title,
		Active:   active,
		Version:  version.Version,
		Uptime:   time.Since(h.deps.Started).Truncate(time.Second).String(),
		Hostname: cfg.Server.SMTP.Hostname,
		Cfg:      cfg,
	}
	if sess := h.sessionFrom(r); sess != nil {
		pd.User = sess.Username
		pd.CSRF = sess.CSRFToken
	}
	if h.deps.Metrics != nil {
		pd.Metrics = h.deps.Metrics.Snapshot()
	}
	if h.deps.Spool != nil {
		if q, err := h.deps.Spool.Stats(); err == nil {
			pd.Queue = q
		}
	}
	return pd
}

func (h *Handler) render(w http.ResponseWriter, name string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'")
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		h.deps.Log.Error("template", "name", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		has, err := h.deps.Auth.HasUsers(ctx)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if !has {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}
		sess := h.sessionFrom(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.Method == http.MethodPost {
			if r.FormValue("csrf") != sess.CSRFToken {
				http.Error(w, "CSRF", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

func (h *Handler) sessionFrom(r *http.Request) *auth.Session {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	sess, err := h.deps.Auth.GetSession(r.Context(), c.Value)
	if err != nil {
		return nil
	}
	return sess
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
}

func (h *Handler) setup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	has, _ := h.deps.Auth.HasUsers(ctx)
	if has {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	pd := h.base(r, "Setup", "setup")
	pd.NeedsSetup = true
	if r.Method == http.MethodPost {
		user := strings.TrimSpace(r.FormValue("username"))
		pass := r.FormValue("password")
		if user == "" || len(pass) < 8 {
			pd.Error = "логин обязателен, пароль ≥ 8 символов"
			h.render(w, "setup.html", pd)
			return
		}
		if err := h.deps.Auth.CreateAdmin(ctx, user, pass); err != nil {
			pd.Error = err.Error()
			h.render(w, "setup.html", pd)
			return
		}
		u, err := h.deps.Auth.Authenticate(ctx, user, pass)
		if err != nil {
			pd.Error = "admin создан, но вход не удался: " + err.Error()
			h.render(w, "setup.html", pd)
			return
		}
		sess, err := h.deps.Auth.CreateSession(ctx, u.ID, sessionTTL)
		if err != nil {
			pd.Error = err.Error()
			h.render(w, "setup.html", pd)
			return
		}
		h.setSessionCookie(w, sess.Token, sess.ExpiresAt)
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	h.render(w, "setup.html", pd)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	has, _ := h.deps.Auth.HasUsers(ctx)
	if !has {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	pd := h.base(r, "Login", "login")
	if r.Method == http.MethodPost {
		u, err := h.deps.Auth.Authenticate(ctx, r.FormValue("username"), r.FormValue("password"))
		if err != nil {
			pd.Error = "неверный логин или пароль"
			h.render(w, "login.html", pd)
			return
		}
		sess, err := h.deps.Auth.CreateSession(ctx, u.ID, sessionTTL)
		if err != nil {
			pd.Error = err.Error()
			h.render(w, "login.html", pd)
			return
		}
		h.setSessionCookie(w, sess.Token, sess.ExpiresAt)
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	h.render(w, "login.html", pd)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = h.deps.Auth.DeleteSession(r.Context(), c.Value)
	}
	h.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	pd := h.base(r, "Dashboard", "dashboard")
	h.render(w, "dashboard.html", pd)
}

func (h *Handler) settings(w http.ResponseWriter, r *http.Request) {
	pd := h.base(r, "Settings", "settings")
	if r.Method == http.MethodPost {
		h.deps.CfgMu.Lock()
		old := *h.deps.Cfg
		patch := config.SettingsPatch{
			SMTPListen:        r.FormValue("smtp_listen"),
			ImplicitTLSListen: r.FormValue("implicit_tls"),
			Hostname:          r.FormValue("hostname"),
			WebListen:         r.FormValue("web_listen"),
			SmartHost:         r.FormValue("smart_host"),
			RelayHelo:         r.FormValue("relay_helo"),
			LogLevel:          r.FormValue("log_level"),
			LogFormat:         r.FormValue("log_format"),
			DefaultAction:     r.FormValue("default_action"),
			SMTPTLS:          r.FormValue("smtp_tls") == "on",
			WebTLS:            r.FormValue("web_tls") == "on",
			ACMEEnabled:       r.FormValue("acme_enabled") == "on",
			ACMEEmail:         r.FormValue("acme_email"),
			ACMEHTTPBind:      r.FormValue("acme_http_bind"),
			ACMEAgreeTOS:      r.FormValue("acme_agree") == "on",
			ACMEDomains:       r.FormValue("acme_domains"),
			ACMEDirectory:     r.FormValue("acme_directory"),
			ACMEChallenge:     r.FormValue("acme_challenge"),
		}
		if v := r.FormValue("max_message_bytes"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				patch.MaxMessageBytes = n
			}
		}
		if v := r.FormValue("max_recipients"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				patch.MaxRecipients = n
			}
		}
		if v := r.FormValue("relay_workers"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				patch.RelayWorkers = n
			}
		}
		h.deps.Cfg.ApplyPatch(patch)
		config.ApplyDefaults(h.deps.Cfg)
		if err := h.deps.Cfg.Validate(); err != nil {
			*h.deps.Cfg = old
			h.deps.CfgMu.Unlock()
			pd.Error = err.Error()
			h.render(w, "settings.html", pd)
			return
		}
		neu := *h.deps.Cfg
		restart := config.NeedsRestart(&old, &neu)
		err := config.Save(h.deps.CfgPath, h.deps.Cfg)
		h.reloadPolicyFilters()
		h.deps.CfgMu.Unlock()
		if err != nil {
			pd.Error = err.Error()
			h.render(w, "settings.html", pd)
			return
		}
		pd = h.base(r, "Settings", "settings")
		pd.Flash = "сохранено"
		pd.Restart = restart
		if restart {
			pd.Flash = "сохранено — требуется перезапуск для смены портов/TLS web"
		}
	}
	h.render(w, "settings.html", pd)
}

func (h *Handler) certsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pd := h.base(r, "Certificates", "certs")
	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		switch action {
		case "selfsigned":
			dom := r.FormValue("domain")
			if dom == "" {
				dom = pd.Hostname
			}
			pemC, pemK, err := certs.GenerateSelfSigned([]string{dom}, 365*24*time.Hour)
			if err == nil {
				err = h.deps.Certs.Import(pemC, pemK, "live")
			}
			if err != nil {
				pd.Error = err.Error()
			} else {
				pd.Flash = "self-signed создан"
			}
		case "import":
			certF, _, err1 := r.FormFile("cert")
			keyF, _, err2 := r.FormFile("key")
			if err1 != nil || err2 != nil {
				pd.Error = "нужны файлы cert и key"
			} else {
				cb, _ := io.ReadAll(certF)
				kb, _ := io.ReadAll(keyF)
				_ = certF.Close()
				_ = keyF.Close()
				if err := h.deps.Certs.Import(cb, kb, "live"); err != nil {
					pd.Error = err.Error()
				} else {
					pd.Flash = "импортировано"
				}
			}
		case "delete":
			name := r.FormValue("name")
			if err := h.deps.Certs.Delete(name); err != nil {
				pd.Error = err.Error()
			} else {
				pd.Flash = "удалено"
			}
		case "ca_add":
			f, hdr, err := r.FormFile("ca")
			if err != nil {
				pd.Error = "нужен файл УЦ"
			} else {
				defer f.Close()
				data, _ := io.ReadAll(f)
				if err := writeTempAndAddCA(h.deps.Certs, data, hdr.Filename); err != nil {
					pd.Error = err.Error()
				} else {
					pd.Flash = "УЦ добавлен"
				}
			}
		case "ca_remove":
			if err := h.deps.Certs.RemoveCA(r.FormValue("name")); err != nil {
				pd.Error = err.Error()
			} else {
				pd.Flash = "УЦ удалён"
			}
		case "acme_issue":
			doms := strings.FieldsFunc(r.FormValue("domains"), func(r rune) bool { return r == ',' || r == ' ' })
			info, err := h.deps.Certs.IssueACME(ctx, doms)
			if err != nil {
				pd.Error = err.Error()
			} else {
				pd.Flash = "ACME: " + info.NotAfter.Format(time.RFC3339)
			}
		}
	}
	list, _ := h.deps.Certs.List()
	pd.Certs = list
	pd.CAList, _ = h.deps.Certs.ListCA()
	pd.ACME = h.deps.Certs.ACMEStatus()
	h.render(w, "certs.html", pd)
}

func writeTempAndAddCA(m *certs.Manager, data []byte, name string) error {
	tmp := filepath.Join(m.Dir(), ".ca-upload.pem")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	return m.AddCA(tmp, name)
}

func (h *Handler) domainsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pd := h.base(r, "Domains", "domains")
	if r.Method == http.MethodPost {
		switch r.FormValue("action") {
		case "add_domain":
			err := h.deps.Domains.AddDomain(ctx, r.FormValue("name"), r.FormValue("catch_all"), r.FormValue("accept") == "on")
			if err != nil {
				pd.Error = err.Error()
			} else {
				pd.Flash = "домен добавлен"
			}
		case "del_domain":
			id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
			_ = h.deps.Domains.DeleteDomain(ctx, id)
			pd.Flash = "удалено"
		case "add_route":
			err := h.deps.Domains.AddRoute(ctx, r.FormValue("domain"), r.FormValue("next_hop"))
			if err != nil {
				pd.Error = err.Error()
			} else {
				pd.Flash = "маршрут сохранён"
			}
		case "del_route":
			id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
			_ = h.deps.Domains.DeleteRoute(ctx, id)
			pd.Flash = "маршрут удалён"
		case "add_alias":
			err := h.deps.Domains.AddAlias(ctx, r.FormValue("address"), r.FormValue("destinations"))
			if err != nil {
				pd.Error = err.Error()
			} else {
				pd.Flash = "alias сохранён"
			}
		case "del_alias":
			id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
			_ = h.deps.Domains.DeleteAlias(ctx, id)
			pd.Flash = "alias удалён"
		}
	}
	pd.Domains, _ = h.deps.Domains.ListDomains(ctx)
	pd.Routes, _ = h.deps.Domains.ListRoutes(ctx)
	pd.Aliases, _ = h.deps.Domains.ListAliases(ctx)
	h.render(w, "domains.html", pd)
}

func (h *Handler) dkimPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pd := h.base(r, "DKIM", "dkim")
	if r.Method == http.MethodPost {
		switch r.FormValue("action") {
		case "generate":
			_, err := h.deps.DKIM.Generate(ctx, r.FormValue("domain"), r.FormValue("selector"), r.FormValue("algorithm"), r.FormValue("sign") == "on")
			if err != nil {
				pd.Error = err.Error()
			} else {
				pd.Flash = "ключ создан"
			}
		case "delete":
			id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
			_ = h.deps.DKIM.Delete(ctx, id)
			pd.Flash = "удалено"
		}
	}
	keys, _ := h.deps.DKIM.List(ctx)
	pd.DKIMKeys = keys
	pd.DNSHints = map[int64]string{}
	for _, k := range keys {
		pd.DNSHints[k.ID] = h.deps.DKIM.DNSRecord(k)
	}
	h.render(w, "dkim.html", pd)
}

func (h *Handler) reloadPolicyFilters() {
	if h.deps.Policy != nil {
		h.deps.Policy.SetConfig(h.deps.Cfg)
	}
	if h.deps.Filters != nil {
		_ = h.deps.Filters.Reload(h.deps.Cfg)
	}
}

func (h *Handler) policiesPage(w http.ResponseWriter, r *http.Request) {
	pd := h.base(r, "Policies", "policies")
	if r.Method == http.MethodPost {
		h.deps.CfgMu.Lock()
		old := clonePolicy(h.deps.Cfg.Policy)
		action := r.FormValue("action")
		switch action {
		case "default":
			h.deps.Cfg.Policy.DefaultAction = r.FormValue("default_action")
		case "add":
			en := r.FormValue("enabled") == "on"
			prio, _ := strconv.Atoi(r.FormValue("priority"))
			rule := config.PolicyRule{
				ID:       strings.TrimSpace(r.FormValue("id")),
				Enabled:  &en,
				Priority: prio,
				Action:   r.FormValue("rule_action"),
				Reason:   r.FormValue("reason"),
				Tag:      r.FormValue("tag"),
				Match: config.PolicyMatch{
					From:      r.FormValue("from"),
					To:        r.FormValue("to"),
					RemoteIP:  r.FormValue("remote_ip"),
					Helo:      r.FormValue("helo"),
					SubjectRe: r.FormValue("subject_re"),
				},
			}
			if rule.ID == "" {
				rule.ID = fmt.Sprintf("rule-%d", time.Now().UnixNano()%100000)
			}
			h.deps.Cfg.Policy.Rules = append(h.deps.Cfg.Policy.Rules, rule)
		case "delete":
			id := r.FormValue("id")
			out := h.deps.Cfg.Policy.Rules[:0]
			for _, rule := range h.deps.Cfg.Policy.Rules {
				if rule.ID != id {
					out = append(out, rule)
				}
			}
			h.deps.Cfg.Policy.Rules = out
		case "toggle":
			id := r.FormValue("id")
			for i := range h.deps.Cfg.Policy.Rules {
				if h.deps.Cfg.Policy.Rules[i].ID == id {
					cur := h.deps.Cfg.Policy.Rules[i].PolicyRuleEnabled()
					v := !cur
					h.deps.Cfg.Policy.Rules[i].Enabled = &v
				}
			}
		}
		config.ApplyDefaults(h.deps.Cfg)
		if err := h.deps.Cfg.Validate(); err != nil {
			h.deps.Cfg.Policy = old
			h.deps.CfgMu.Unlock()
			pd.Error = err.Error()
			h.render(w, "policies.html", pd)
			return
		}
		err := config.Save(h.deps.CfgPath, h.deps.Cfg)
		h.reloadPolicyFilters()
		h.deps.CfgMu.Unlock()
		if err != nil {
			pd.Error = err.Error()
		} else {
			pd = h.base(r, "Policies", "policies")
			pd.Flash = "сохранено"
		}
	}
	h.render(w, "policies.html", pd)
}

func (h *Handler) filtersPage(w http.ResponseWriter, r *http.Request) {
	pd := h.base(r, "Filters", "filters")
	if r.Method == http.MethodPost {
		h.deps.CfgMu.Lock()
		oldDNSBL := h.deps.Cfg.Filters.DNSBL
		oldAnti := h.deps.Cfg.Filters.Antispam
		switch r.FormValue("action") {
		case "dnsbl":
			h.deps.Cfg.Filters.DNSBL.Enabled = r.FormValue("dnsbl_enabled") == "on"
			if v := r.FormValue("cache_ttl"); v != "" {
				if d, err := time.ParseDuration(v); err == nil {
					h.deps.Cfg.Filters.DNSBL.CacheTTL = d
				}
			}
			h.deps.Cfg.Filters.DNSBL.Whitelist = splitLines(r.FormValue("whitelist"))
			zonesRaw := strings.TrimSpace(r.FormValue("zones"))
			var zones []config.DNSBLZone
			for _, line := range strings.Split(zonesRaw, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.Fields(line)
				z := config.DNSBLZone{Zone: parts[0], Action: "score", Weight: 5}
				if len(parts) > 1 {
					if w, err := strconv.ParseFloat(parts[1], 64); err == nil {
						z.Weight = w
					}
				}
				if len(parts) > 2 {
					z.Action = parts[2]
				}
				zones = append(zones, z)
			}
			h.deps.Cfg.Filters.DNSBL.Zones = zones
		case "antispam":
			h.deps.Cfg.Filters.Antispam.Enabled = r.FormValue("antispam_enabled") == "on"
			if v := r.FormValue("tag_score"); v != "" {
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					h.deps.Cfg.Filters.Antispam.TagScore = f
				}
			}
			if v := r.FormValue("quarantine_score"); v != "" {
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					h.deps.Cfg.Filters.Antispam.QuarantineScore = f
				}
			}
			if v := r.FormValue("reject_score"); v != "" {
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					h.deps.Cfg.Filters.Antispam.RejectScore = f
				}
			}
		case "add_rule":
			wht, _ := strconv.ParseFloat(r.FormValue("weight"), 64)
			h.deps.Cfg.Filters.Antispam.Rules = append(h.deps.Cfg.Filters.Antispam.Rules, config.AntispamRule{
				ID:     r.FormValue("id"),
				Weight: wht,
				Header: r.FormValue("header"),
				Regex:  r.FormValue("regex"),
				URI:    r.FormValue("uri") == "on",
			})
		case "del_rule":
			id := r.FormValue("id")
			out := h.deps.Cfg.Filters.Antispam.Rules[:0]
			for _, rule := range h.deps.Cfg.Filters.Antispam.Rules {
				if rule.ID != id {
					out = append(out, rule)
				}
			}
			h.deps.Cfg.Filters.Antispam.Rules = out
		}
		config.ApplyDefaults(h.deps.Cfg)
		if err := h.deps.Cfg.Validate(); err != nil {
			h.deps.Cfg.Filters.DNSBL = oldDNSBL
			h.deps.Cfg.Filters.Antispam = oldAnti
			h.deps.CfgMu.Unlock()
			pd.Error = err.Error()
			h.render(w, "filters.html", pd)
			return
		}
		err := config.Save(h.deps.CfgPath, h.deps.Cfg)
		h.reloadPolicyFilters()
		h.deps.CfgMu.Unlock()
		if err != nil {
			pd.Error = err.Error()
		} else {
			pd = h.base(r, "Filters", "filters")
			pd.Flash = "сохранено"
		}
	}
	h.render(w, "filters.html", pd)
}

func clonePolicy(p config.PolicyConfig) config.PolicyConfig {
	out := p
	out.Rules = append([]config.PolicyRule(nil), p.Rules...)
	return out
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}