package filter

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/mail"
	"strings"
	"sync"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/mailmsg"
	"github.com/rkislov/mailedge/internal/spf"
)

// AuthFilter performs inbound SPF, DKIM and DMARC checks.
type AuthFilter struct {
	mu  sync.RWMutex
	cfg config.DMARCConfig

	// Injectable for tests.
	LookupTXT func(name string) ([]string, error)
	LookupIP  func(host string) ([]net.IP, error)
	LookupMX  func(name string) ([]*net.MX, error)
	VerifyDKIM func(r io.Reader) ([]*dkim.Verification, error)
}

// NewAuthFilter creates an authentication filter.
func NewAuthFilter() *AuthFilter { return &AuthFilter{} }

func (a *AuthFilter) Name() string { return "dmarc" }

func (a *AuthFilter) Init(cfg *config.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cfg == nil {
		a.cfg = config.DMARCConfig{}
		return nil
	}
	a.cfg = cfg.Filters.DMARC
	if a.cfg.AuthservID == "" && cfg.Server.SMTP.Hostname != "" {
		a.cfg.AuthservID = cfg.Server.SMTP.Hostname
	}
	return nil
}

func (a *AuthFilter) Close() error { return nil }

func (a *AuthFilter) Process(ctx context.Context, msg *mailmsg.Message, data []byte) (*mailmsg.Result, error) {
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	if !cfg.Enabled {
		return &mailmsg.Result{Action: "accept"}, nil
	}

	fromDomain := extractFromDomain(msg, data)
	ip := net.ParseIP("")
	if msg != nil {
		ip = net.ParseIP(msg.RemoteIP)
		if ip == nil {
			host, _, err := net.SplitHostPort(msg.RemoteIP)
			if err == nil {
				ip = net.ParseIP(host)
			}
		}
	}

	spfOpts := &spf.Options{}
	if a.LookupTXT != nil {
		spfOpts.LookupTXT = a.LookupTXT
	}
	if a.LookupIP != nil {
		spfOpts.LookupIP = a.LookupIP
	}
	if a.LookupMX != nil {
		spfOpts.LookupMX = a.LookupMX
	}
	helo := ""
	mailFrom := ""
	if msg != nil {
		helo = msg.Helo
		mailFrom = msg.From
	}
	spfRes, spfDomain := spf.Check(ip, mailFrom, helo, spfOpts)

	dkimRes := "none"
	var dkimDomains []string
	verify := a.VerifyDKIM
	if verify == nil {
		verify = func(r io.Reader) ([]*dkim.Verification, error) {
			return dkim.Verify(r)
		}
	}
	vers, err := verify(bytes.NewReader(data))
	if err == nil {
		anyPass := false
		anyFail := false
		for _, v := range vers {
			if v == nil {
				continue
			}
			if v.Err == nil {
				anyPass = true
				dkimDomains = append(dkimDomains, strings.ToLower(v.Domain))
			} else {
				anyFail = true
			}
		}
		switch {
		case anyPass:
			dkimRes = "pass"
		case anyFail:
			dkimRes = "fail"
		default:
			dkimRes = "none"
		}
	} else {
		dkimRes = "permerror"
	}

	authserv := cfg.AuthservID
	if authserv == "" {
		authserv = "mgw"
	}

	var results []authres.Result
	results = append(results, &authres.SPFResult{
		Value: mapSPF(spfRes),
		From:  mailFrom,
		Helo:  helo,
	})
	if dkimRes == "pass" {
		for _, d := range dkimDomains {
			results = append(results, &authres.DKIMResult{Value: authres.ResultPass, Domain: d})
		}
	} else {
		results = append(results, &authres.DKIMResult{Value: mapDKIM(dkimRes)})
	}

	dmarcRes := "none"
	dmarcPolicy := ""
	action := "accept"
	reason := ""

	if fromDomain != "" {
		rec, lerr := dmarcLookup(fromDomain, a.LookupTXT)
		if lerr != nil && !isNoPolicy(lerr) {
			dmarcRes = "temperror"
			switch strings.ToLower(cfg.OnTempFail) {
			case "reject":
				action = "reject"
				reason = "dmarc temperror"
			case "quarantine":
				action = "quarantine"
				reason = "dmarc temperror"
			default:
				action = "accept"
			}
		} else if rec != nil {
			dmarcPolicy = string(rec.Policy)
			spfAligned := spfRes == spf.Pass && aligned(spfDomain, fromDomain, rec.SPFAlignment)
			dkimAligned := false
			for _, d := range dkimDomains {
				if aligned(d, fromDomain, rec.DKIMAlignment) {
					dkimAligned = true
					break
				}
			}
			if spfAligned || dkimAligned {
				dmarcRes = "pass"
			} else {
				dmarcRes = "fail"
				reason = "dmarc fail policy=" + dmarcPolicy
				switch {
				case cfg.OnFail != "":
					action = strings.ToLower(cfg.OnFail)
				case cfg.HonorPolicy:
					action = policyAction(rec, fromDomain)
					if action == "" {
						action = "accept"
					}
				}
			}
			results = append(results, &authres.DMARCResult{
				Value: mapDMARC(dmarcRes),
				From:  fromDomain,
			})
		}
	}

	hdr := authres.Format(authserv, results)
	res := &mailmsg.Result{
		Action: action,
		Reason: reason,
		Tags: []string{
			"spf:" + string(spfRes),
			"dkim:" + dkimRes,
			"dmarc:" + dmarcRes,
		},
		Details: map[string]string{
			"spf":          string(spfRes),
			"spf_domain":   spfDomain,
			"dkim":         dkimRes,
			"dmarc":        dmarcRes,
			"dmarc_policy": dmarcPolicy,
			"from_domain":  fromDomain,
		},
	}
	if cfg.AddHeader {
		res.PrependHeaders = []string{"Authentication-Results: " + stripAuthResPrefix(hdr)}
	}
	if action == "reject" || action == "quarantine" || action == "hold" {
		if reason == "" {
			reason = "authentication failed"
			res.Reason = reason
		}
	}
	_ = ctx
	return res, nil
}

func stripAuthResPrefix(s string) string {
	// authres.Format returns "Authentication-Results: ..."
	const p = "Authentication-Results:"
	if strings.HasPrefix(s, p) {
		return strings.TrimSpace(s[len(p):])
	}
	return s
}

func dmarcLookup(domain string, lookupTXT func(string) ([]string, error)) (*dmarc.Record, error) {
	if lookupTXT == nil {
		return dmarc.Lookup(domain)
	}
	return dmarc.LookupWithOptions(domain, &dmarc.LookupOptions{LookupTXT: lookupTXT})
}

func isNoPolicy(err error) bool {
	return err == dmarc.ErrNoPolicy
}

func policyAction(rec *dmarc.Record, fromDomain string) string {
	pol := rec.Policy
	org, err := publicsuffix.EffectiveTLDPlusOne(fromDomain)
	if err == nil && !strings.EqualFold(fromDomain, org) && rec.SubdomainPolicy != "" {
		pol = rec.SubdomainPolicy
	}
	switch pol {
	case dmarc.PolicyReject:
		return "reject"
	case dmarc.PolicyQuarantine:
		return "quarantine"
	default:
		return "tag"
	}
}

func aligned(authDomain, fromDomain string, mode dmarc.AlignmentMode) bool {
	authDomain = strings.ToLower(strings.TrimSuffix(authDomain, "."))
	fromDomain = strings.ToLower(strings.TrimSuffix(fromDomain, "."))
	if authDomain == "" || fromDomain == "" {
		return false
	}
	if mode == dmarc.AlignmentStrict {
		return authDomain == fromDomain
	}
	// relaxed
	if authDomain == fromDomain {
		return true
	}
	aOrg, err1 := publicsuffix.EffectiveTLDPlusOne(authDomain)
	fOrg, err2 := publicsuffix.EffectiveTLDPlusOne(fromDomain)
	if err1 != nil || err2 != nil {
		return strings.HasSuffix(authDomain, "."+fromDomain) || strings.HasSuffix(fromDomain, "."+authDomain)
	}
	return strings.EqualFold(aOrg, fOrg)
}

func extractFromDomain(msg *mailmsg.Message, data []byte) string {
	if m, err := mail.ReadMessage(bytes.NewReader(data)); err == nil {
		if from := m.Header.Get("From"); from != "" {
			if addrs, err := mail.ParseAddressList(from); err == nil && len(addrs) > 0 {
				if i := strings.LastIndex(addrs[0].Address, "@"); i >= 0 {
					return strings.ToLower(addrs[0].Address[i+1:])
				}
			}
		}
	}
	if msg != nil {
		if i := strings.LastIndex(msg.From, "@"); i >= 0 {
			return strings.ToLower(strings.Trim(msg.From[i+1:], ">"))
		}
	}
	return ""
}

func mapSPF(r spf.Result) authres.ResultValue {
	switch r {
	case spf.Pass:
		return authres.ResultPass
	case spf.Fail:
		return authres.ResultFail
	case spf.SoftFail:
		return authres.ResultSoftFail
	case spf.Neutral:
		return authres.ResultNeutral
	case spf.TempError:
		return authres.ResultTempError
	case spf.PermError:
		return authres.ResultPermError
	default:
		return authres.ResultNone
	}
}

func mapDKIM(s string) authres.ResultValue {
	switch s {
	case "pass":
		return authres.ResultPass
	case "fail":
		return authres.ResultFail
	case "temperror":
		return authres.ResultTempError
	case "permerror":
		return authres.ResultPermError
	default:
		return authres.ResultNone
	}
}

func mapDMARC(s string) authres.ResultValue {
	switch s {
	case "pass":
		return authres.ResultPass
	case "fail":
		return authres.ResultFail
	case "temperror":
		return authres.ResultTempError
	case "permerror":
		return authres.ResultPermError
	default:
		return authres.ResultNone
	}
}

// PrependHeaders inserts header lines at the top of a message.
func PrependHeaders(data []byte, headers []string) []byte {
	if len(headers) == 0 {
		return data
	}
	var b strings.Builder
	for _, h := range headers {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		b.WriteString(h)
		b.WriteString("\r\n")
	}
	b.Write(data)
	return []byte(b.String())
}
