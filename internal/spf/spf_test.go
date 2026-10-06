package spf_test

import (
	"net"
	"testing"

	"github.com/rkislov/mailedge/internal/spf"
)

func TestCheckIP4PassFail(t *testing.T) {
	opts := &spf.Options{
		LookupTXT: func(name string) ([]string, error) {
			if name == "ex.test" {
				return []string{"v=spf1 ip4:192.0.2.1 -all"}, nil
			}
			return nil, &net.DNSError{Err: "nxdomain", Name: name, IsNotFound: true}
		},
		LookupIP: func(host string) ([]net.IP, error) { return nil, nil },
		LookupMX: func(name string) ([]*net.MX, error) { return nil, nil },
	}
	res, dom := spf.Check(net.ParseIP("192.0.2.1"), "a@ex.test", "helo", opts)
	if res != spf.Pass || dom != "ex.test" {
		t.Fatalf("pass: %s %s", res, dom)
	}
	res, _ = spf.Check(net.ParseIP("192.0.2.9"), "a@ex.test", "helo", opts)
	if res != spf.Fail {
		t.Fatalf("fail: %s", res)
	}
}

func TestCheckInclude(t *testing.T) {
	opts := &spf.Options{
		LookupTXT: func(name string) ([]string, error) {
			switch name {
			case "parent.test":
				return []string{"v=spf1 include:child.test -all"}, nil
			case "child.test":
				return []string{"v=spf1 ip4:198.51.100.5 -all"}, nil
			default:
				return nil, &net.DNSError{Err: "nxdomain", Name: name, IsNotFound: true}
			}
		},
		LookupIP: func(host string) ([]net.IP, error) { return nil, nil },
		LookupMX: func(name string) ([]*net.MX, error) { return nil, nil },
	}
	res, _ := spf.Check(net.ParseIP("198.51.100.5"), "u@parent.test", "", opts)
	if res != spf.Pass {
		t.Fatalf("got %s", res)
	}
}
