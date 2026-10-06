package mimeutil

import (
	"bytes"
	"strings"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
)

// Parsed holds commonly used fields extracted from a raw RFC5322 message.
type Parsed struct {
	Subject string
	From    string
	To      []string
	Header  message.Header
}

// Parse extracts headers from raw message bytes.
func Parse(raw []byte) (*Parsed, error) {
	entity, err := message.Read(bytes.NewReader(raw))
	if err != nil && entity == nil {
		return parseHeadersFallback(raw), nil
	}
	if entity == nil {
		return parseHeadersFallback(raw), nil
	}
	h := entity.Header
	p := &Parsed{
		Subject: h.Get("Subject"),
		From:    h.Get("From"),
		Header:  h,
	}
	if to := h.Get("To"); to != "" {
		p.To = splitAddrs(to)
	}
	return p, nil
}

func parseHeadersFallback(raw []byte) *Parsed {
	p := &Parsed{}
	r := bytes.NewReader(raw)
	for {
		line, err := readLine(r)
		if err != nil || line == "" {
			break
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "subject:"):
			p.Subject = strings.TrimSpace(line[8:])
		case strings.HasPrefix(lower, "from:"):
			p.From = strings.TrimSpace(line[5:])
		case strings.HasPrefix(lower, "to:"):
			p.To = splitAddrs(strings.TrimSpace(line[3:]))
		}
	}
	return p
}

func readLine(r *bytes.Reader) (string, error) {
	var b strings.Builder
	for {
		c, err := r.ReadByte()
		if err != nil {
			if b.Len() == 0 {
				return "", err
			}
			return b.String(), nil
		}
		if c == '\n' {
			return strings.TrimRight(b.String(), "\r"), nil
		}
		b.WriteByte(c)
	}
}

func splitAddrs(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
