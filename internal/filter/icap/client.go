package icap

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Client talks ICAP/1.0 RESPMOD to an AV gateway (c-icap, Kaspersky, etc.).
type Client struct {
	Addr    string
	Service string
	TLS     bool
	Timeout time.Duration
	Dial    func(ctx context.Context, network, address string) (net.Conn, error)
}

// Result is the parsed ICAP scan outcome.
type Result struct {
	Status     int
	Infected   bool
	Threat     string
	Headers    map[string]string
	RawStatus  string
}

// RESPMOD sends body as an encapsulated HTTP response for scanning.
func (c *Client) RESPMOD(ctx context.Context, filename string, body []byte) (*Result, error) {
	if c.Addr == "" {
		return nil, fmt.Errorf("icap: empty addr")
	}
	service := c.Service
	if service == "" {
		service = "avscan"
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if filename == "" {
		filename = "message.eml"
	}

	httpHdr := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(body))
	encStart := 0
	resBodyOff := len(httpHdr)

	req := &strings.Builder{}
	fmt.Fprintf(req, "RESPMOD icap://%s/%s ICAP/1.0\r\n", c.Addr, service)
	fmt.Fprintf(req, "Host: %s\r\n", c.Addr)
	fmt.Fprintf(req, "User-Agent: mgw-icap/1.0\r\n")
	fmt.Fprintf(req, "Allow: 204\r\n")
	fmt.Fprintf(req, "X-Client-IP: 127.0.0.1\r\n")
	fmt.Fprintf(req, "X-File-Path: %s\r\n", filename)
	fmt.Fprintf(req, "Encapsulated: res-hdr=%d, res-body=%d\r\n", encStart, resBodyOff)
	req.WriteString("\r\n")
	req.WriteString(httpHdr)

	dial := c.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: timeout}
		dial = d.DialContext
	}

	conn, err := dial(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, fmt.Errorf("icap dial: %w", err)
	}
	defer conn.Close()

	if c.TLS {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: hostOnly(c.Addr), MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("icap tls: %w", err)
		}
		conn = tlsConn
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	_ = conn.SetDeadline(deadline)

	if _, err := io.WriteString(conn, req.String()); err != nil {
		return nil, fmt.Errorf("icap write hdr: %w", err)
	}
	// chunked body (ICAP uses HTTP chunked for encapsulated body)
	if err := writeChunk(conn, body); err != nil {
		return nil, fmt.Errorf("icap write body: %w", err)
	}
	if err := writeChunk(conn, nil); err != nil { // last-chunk
		return nil, err
	}

	return readResponse(conn)
}

func writeChunk(w io.Writer, b []byte) error {
	if _, err := fmt.Fprintf(w, "%x\r\n", len(b)); err != nil {
		return err
	}
	if len(b) > 0 {
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func readResponse(r io.Reader) (*Result, error) {
	br := bufio.NewReader(r)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("icap read status: %w", err)
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "ICAP/") {
		return nil, fmt.Errorf("icap: bad status line %q", statusLine)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("icap: bad status code: %w", err)
	}

	headers := map[string]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("icap read hdr: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if i := strings.IndexByte(line, ':'); i > 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+1:])
			headers[httpCanonical(k)] = v
		}
	}

	res := &Result{Status: code, RawStatus: statusLine, Headers: headers}
	if code == 204 {
		return res, nil
	}

	threat := detectThreat(headers)
	if threat != "" {
		res.Infected = true
		res.Threat = threat
	}
	// Some servers return 200 with Encapsulated blocked page even without X-Infection-Found
	if !res.Infected && code == 200 {
		if v := headers["X-Infection-Found"]; v != "" {
			res.Infected = true
			res.Threat = parseThreatFromInfection(v)
		}
	}
	return res, nil
}

func detectThreat(h map[string]string) string {
	keys := []string{
		"X-Infection-Found",
		"X-Virus-ID",
		"X-Virus-Name",
		"X-Clamav-Virus",
		"X-Block-Reason",
		"X-Violations-Found",
	}
	for _, k := range keys {
		if v := h[k]; v != "" {
			if k == "X-Infection-Found" {
				return parseThreatFromInfection(v)
			}
			return v
		}
	}
	return ""
}

func parseThreatFromInfection(v string) string {
	// Type=0; Resolution=2; Threat=Eicar-Test-Signature;
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "threat=") {
			return strings.TrimSpace(part[len("threat="):])
		}
	}
	return v
}

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func httpCanonical(s string) string {
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
	}
	return strings.Join(parts, "-")
}
