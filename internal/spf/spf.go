package spf

import (
	"fmt"
	"net"
	"strings"
)

// Result is an SPF evaluation outcome.
type Result string

const (
	None      Result = "none"
	Neutral   Result = "neutral"
	Pass      Result = "pass"
	Fail      Result = "fail"
	SoftFail  Result = "softfail"
	TempError Result = "temperror"
	PermError Result = "permerror"
)

// LookupTXT is injectable for tests.
type LookupTXT func(name string) ([]string, error)

// LookupIP is injectable for tests (A/AAAA).
type LookupIP func(host string) ([]net.IP, error)

// LookupMX is injectable for tests.
type LookupMX func(name string) ([]*net.MX, error)

// Options customizes DNS lookups.
type Options struct {
	LookupTXT LookupTXT
	LookupIP  LookupIP
	LookupMX  LookupMX
}

// Check evaluates SPF for ip against the domain in mailFrom (or helo if empty mailFrom).
func Check(ip net.IP, mailFrom, helo string, opts *Options) (Result, string) {
	if opts == nil {
		opts = &Options{}
	}
	if opts.LookupTXT == nil {
		opts.LookupTXT = net.LookupTXT
	}
	if opts.LookupIP == nil {
		opts.LookupIP = net.LookupIP
	}
	if opts.LookupMX == nil {
		opts.LookupMX = net.LookupMX
	}
	if ip == nil {
		return None, ""
	}

	domain := domainFromMailbox(mailFrom)
	if domain == "" {
		domain = strings.ToLower(strings.TrimSpace(helo))
	}
	if domain == "" {
		return None, ""
	}
	return checkHost(ip, domain, opts, 0)
}

func checkHost(ip net.IP, domain string, opts *Options, depth int) (Result, string) {
	if depth > 10 {
		return PermError, domain
	}
	txts, err := opts.LookupTXT(domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return None, domain
		}
		if ne, ok := err.(net.Error); ok && ne.Temporary() {
			return TempError, domain
		}
		return TempError, domain
	}
	record := ""
	for _, t := range txts {
		t = strings.TrimSpace(t)
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			record = t
			break
		}
	}
	if record == "" {
		return None, domain
	}

	parts := strings.Fields(record)
	if len(parts) == 0 || !strings.EqualFold(parts[0], "v=spf1") {
		return PermError, domain
	}

	var redirect string
	for _, term := range parts[1:] {
		qual := '+'
		mech := term
		switch term[0] {
		case '+', '-', '~', '?':
			qual = rune(term[0])
			mech = term[1:]
		}
		res, matched, err := matchMechanism(ip, domain, mech, opts, depth)
		if err != nil {
			if te, ok := err.(tempErr); ok && bool(te) {
				return TempError, domain
			}
			return PermError, domain
		}
		if strings.HasPrefix(strings.ToLower(mech), "redirect=") {
			redirect = strings.SplitN(mech, "=", 2)[1]
			continue
		}
		if !matched {
			continue
		}
		return qualify(qual, res), domain
	}
	if redirect != "" {
		return checkHost(ip, strings.TrimSuffix(redirect, "."), opts, depth+1)
	}
	return Neutral, domain
}

type tempErr bool

func (t tempErr) Error() string { return "spf temporary" }

func matchMechanism(ip net.IP, domain, mech string, opts *Options, depth int) (Result, bool, error) {
	lower := strings.ToLower(mech)
	switch {
	case lower == "all":
		return Pass, true, nil
	case strings.HasPrefix(lower, "ip4:"):
		return matchIP(ip, mech[4:], true)
	case strings.HasPrefix(lower, "ip6:"):
		return matchIP(ip, mech[4:], false)
	case lower == "a" || strings.HasPrefix(lower, "a:") || strings.HasPrefix(lower, "a/"):
		host, cidr := splitDualCIDR(mech, domain, "a")
		return matchAddrRecords(ip, host, cidr, opts)
	case lower == "mx" || strings.HasPrefix(lower, "mx:") || strings.HasPrefix(lower, "mx/"):
		host, cidr := splitDualCIDR(mech, domain, "mx")
		mxs, err := opts.LookupMX(host)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				return None, false, tempErr(true)
			}
			return None, false, err
		}
		for _, mx := range mxs {
			ok, matched, err := matchAddrRecords(ip, strings.TrimSuffix(mx.Host, "."), cidr, opts)
			if err != nil || matched {
				return ok, matched, err
			}
		}
		return None, false, nil
	case strings.HasPrefix(lower, "include:"):
		inc := strings.TrimSpace(mech[len("include:"):])
		res, _ := checkHost(ip, strings.TrimSuffix(inc, "."), opts, depth+1)
		switch res {
		case Pass:
			return Pass, true, nil
		case TempError:
			return None, false, tempErr(true)
		case PermError:
			return None, false, fmt.Errorf("include permerror")
		default:
			return None, false, nil
		}
	case strings.HasPrefix(lower, "redirect="):
		return None, false, nil
	default:
		// unsupported mechanism — ignore
		return None, false, nil
	}
}

func splitDualCIDR(mech, domain, name string) (host string, cidr int) {
	cidr = -1
	rest := mech
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[i+1:]
	} else if strings.HasPrefix(strings.ToLower(mech), name+"/") {
		rest = mech[len(name):]
	} else {
		return domain, -1
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		host = rest[:i]
		fmt.Sscanf(rest[i+1:], "%d", &cidr)
		if host == "" {
			host = domain
		}
		return host, cidr
	}
	if rest == "" || strings.HasPrefix(rest, "/") {
		return domain, cidr
	}
	return strings.TrimSuffix(rest, "."), -1
}

func matchIP(ip net.IP, spec string, v4 bool) (Result, bool, error) {
	spec = strings.TrimSpace(spec)
	if strings.Contains(spec, "/") {
		_, n, err := net.ParseCIDR(spec)
		if err != nil {
			return None, false, err
		}
		return Pass, n.Contains(ip), nil
	}
	parsed := net.ParseIP(spec)
	if parsed == nil {
		return None, false, fmt.Errorf("bad ip")
	}
	if v4 {
		return Pass, ip.To4() != nil && ip.To4().Equal(parsed.To4()), nil
	}
	return Pass, ip.To16() != nil && ip.Equal(parsed), nil
}

func matchAddrRecords(ip net.IP, host string, cidr int, opts *Options) (Result, bool, error) {
	ips, err := opts.LookupIP(host)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Temporary() {
			return None, false, tempErr(true)
		}
		return None, false, nil
	}
	for _, a := range ips {
		if cidr < 0 {
			if ipEqual(ip, a) {
				return Pass, true, nil
			}
			continue
		}
		ones := cidr
		bits := 32
		if a.To4() == nil {
			bits = 128
		}
		if ones > bits {
			ones = bits
		}
		mask := net.CIDRMask(ones, bits)
		if ip.Mask(mask).Equal(a.Mask(mask)) {
			return Pass, true, nil
		}
	}
	return None, false, nil
}

func ipEqual(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	if a4 != nil && b4 != nil {
		return a4.Equal(b4)
	}
	return a.Equal(b)
}

func qualify(q rune, _ Result) Result {
	switch q {
	case '+':
		return Pass
	case '-':
		return Fail
	case '~':
		return SoftFail
	case '?':
		return Neutral
	default:
		return Pass
	}
}

func domainFromMailbox(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.Trim(addr, "<>")
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return strings.ToLower(addr[i+1:])
	}
	return ""
}
