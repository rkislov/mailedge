package icap_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/mailedge/internal/filter/icap"
)

func TestRESPMODClean204(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveICAP(t, ln, 204, "", false)

	c := &icap.Client{Addr: ln.Addr().String(), Service: "avscan", Timeout: 3 * time.Second}
	res, err := c.RESPMOD(context.Background(), "t.eml", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 204 || res.Infected {
		t.Fatalf("got %+v", res)
	}
}

func TestRESPMODInfected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveICAP(t, ln, 200, "Eicar-Test-Signature", true)

	c := &icap.Client{Addr: ln.Addr().String(), Service: "avscan", Timeout: 3 * time.Second}
	res, err := c.RESPMOD(context.Background(), "eicar.eml", []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Infected || res.Threat != "Eicar-Test-Signature" {
		t.Fatalf("got %+v", res)
	}
}

func serveICAP(t *testing.T, ln net.Listener, code int, threat string, infected bool) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(conn)
	// read request headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	// drain chunked body until 0-chunk
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		n, _ := fmt.Sscanf(line, "%x", new(int))
		_ = n
		size := 0
		fmt.Sscanf(line, "%x", &size)
		if size > 0 {
			_, _ = io.CopyN(io.Discard, br, int64(size))
			_, _ = br.ReadString('\n')
		}
		if size == 0 {
			_, _ = br.ReadString('\n')
			break
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ICAP/1.0 %d %s\r\n", code, statusText(code))
	b.WriteString("ISTag: \"mgw-test\"\r\n")
	b.WriteString("Server: mgw-mock-icap\r\n")
	if infected {
		fmt.Fprintf(&b, "X-Infection-Found: Type=0; Resolution=2; Threat=%s;\r\n", threat)
		b.WriteString("X-Virus-ID: "+threat+"\r\n")
	}
	if code == 204 {
		b.WriteString("\r\n")
	} else {
		b.WriteString("Encapsulated: null-body=0\r\n\r\n")
	}
	_, _ = io.WriteString(conn, b.String())
}

func statusText(code int) string {
	switch code {
	case 204:
		return "No Modifications Needed"
	case 200:
		return "OK"
	default:
		return "OK"
	}
}
