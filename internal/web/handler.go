package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"github.com/rkislov/mailedge/internal/metrics"
	"github.com/rkislov/mailedge/internal/queue"
	"github.com/rkislov/mailedge/internal/version"
	"github.com/rkislov/mailedge/internal/web/i18n"
)

//go:embed static/*
var staticFS embed.FS

//go:embed templates/*
var templatesFS embed.FS

// StatusData is passed to the status page template.
type StatusData struct {
	Lang      string
	ReturnTo  string
	Version   string
	Uptime    string
	Healthy   bool
	Metrics   map[string]int64
	Queue     map[string]int
	Hostname  string
	StartedAt time.Time
}

// Handler serves health endpoints and the street-art status page.
type Handler struct {
	spool     *queue.Spool
	metrics   *metrics.Registry
	hostname  string
	startedAt time.Time
	tmpl      *template.Template
}

// NewHandler builds HTTP handlers for the control/web listener.
func NewHandler(spool *queue.Spool, met *metrics.Registry, hostname string) (*Handler, error) {
	tmpl, err := i18n.Template().ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Handler{
		spool:     spool,
		metrics:   met,
		hostname:  hostname,
		startedAt: time.Now().UTC(),
		tmpl:      tmpl,
	}, nil
}

// Mount registers routes on mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	sub, err := fs.Sub(staticFS, "static")
	if err == nil {
		mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	}
	mux.HandleFunc("/language", i18n.Switch)
	mux.HandleFunc("/healthz", h.healthz)
	mux.HandleFunc("/readyz", h.readyz)
	mux.HandleFunc("/", h.status)
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (h *Handler) readyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	qstats := map[string]int{}
	if h.spool != nil {
		if s, err := h.spool.Stats(); err == nil {
			qstats = s
		}
	}
	data := StatusData{
		Lang:      i18n.Lang(r),
		ReturnTo:  r.URL.RequestURI(),
		Version:   version.Version,
		Uptime:    time.Since(h.startedAt).Truncate(time.Second).String(),
		Healthy:   true,
		Metrics:   h.metrics.Snapshot(),
		Queue:     qstats,
		Hostname:  h.hostname,
		StartedAt: h.startedAt,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Language", data.Lang)
	w.Header().Add("Vary", "Cookie")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'")
	if err := h.tmpl.ExecuteTemplate(w, "status.html", data); err != nil {
		http.Error(w, i18n.Text(data.Lang, "Page rendering failed."), http.StatusInternalServerError)
	}
}
