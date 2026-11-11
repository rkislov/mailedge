// Package i18n localizes the MailEdge web interface.
package i18n

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

const cookieName = "mgw_lang"

//go:embed ru.json
var russianJSON []byte

var russian = loadRussian()

func loadRussian() map[string]string {
	var catalog map[string]string
	if err := json.Unmarshal(russianJSON, &catalog); err != nil {
		panic(err)
	}
	return catalog
}

// Lang returns the selected locale, defaulting to Russian.
func Lang(r *http.Request) string {
	if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value == "en" {
		return "en"
	}
	return "ru"
}

// Text looks up a message using its English text as the catalog key.
func Text(lang, message string, args ...any) string {
	if lang == "ru" && russian[message] != "" {
		message = russian[message]
	}
	if len(args) > 0 {
		return fmt.Sprintf(message, args...)
	}
	return message
}

func yesNo(lang string, yes bool) string {
	if yes {
		return Text(lang, "Yes")
	}
	return Text(lang, "No")
}

var metricNames = map[string]string{
	"smtp_received_total": "Received", "smtp_delivered_total": "Delivered",
	"smtp_rejected_total": "Rejected", "smtp_deferred_total": "Deferred",
	"smtp_bounced_total": "Bounced",
	"incoming":           "Incoming", "active": "Active", "deferred": "Deferred", "bounce": "Bounced",
}

func metric(lang, key string) string {
	if name, ok := metricNames[key]; ok {
		return Text(lang, name)
	}
	return key
}

func labels(lang string, keys ...string) string {
	messages := make(map[string]string, len(keys))
	for _, key := range keys {
		if _, ok := metricNames[key]; ok {
			messages[key] = metric(lang, key)
		} else {
			messages[key] = Text(lang, key)
		}
	}
	data, _ := json.Marshal(messages)
	return string(data)
}

// Template provides the localization helpers and language selector for both UIs.
func Template() *template.Template {
	return template.Must(template.New("").Funcs(template.FuncMap{
		"t": Text, "yesno": yesNo, "labels": labels, "metric": metric,
		"action": func(lang, value string) string {
			switch value {
			case "":
				return Text(lang, "Use default")
			case "accept", "discard", "hold", "pass", "quarantine", "reject", "tag":
				return Text(lang, strings.ToUpper(value[:1])+value[1:])
			default:
				return value
			}
		},
	}).Parse(selector))
}

const selector = `{{define "language-selector"}}
<form method="post" action="/language" class="language-selector" aria-label="{{t .Lang "Language"}}">
  <input type="hidden" name="return_to" value="{{.ReturnTo}}">
  <button type="submit" name="lang" value="ru" lang="ru" aria-label="Русский" aria-pressed="{{eq .Lang "ru"}}">RU</button>
  <button type="submit" name="lang" value="en" lang="en" aria-label="English" aria-pressed="{{eq .Lang "en"}}">EN</button>
</form>
{{end}}`

// Switch saves the requested locale and returns to the current page via GET.
func Switch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	lang := r.PostFormValue("lang")
	if lang != "ru" && lang != "en" {
		http.Error(w, "unsupported language", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: lang, Path: "/", MaxAge: 365 * 24 * 3600,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	target := r.PostFormValue("return_to")
	u, err := url.ParseRequestURI(target)
	if err != nil || !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") ||
		u.IsAbs() || strings.ContainsAny(u.Path, "\\") || strings.HasPrefix(u.Path, "//") {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
