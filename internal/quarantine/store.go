package quarantine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rkislov/mailedge/internal/mailmsg"
)

// Store is a simple on-disk quarantine (metadata + raw message).
type Store struct {
	dir string
}

// New creates a quarantine store under dataDir/quarantine.
func New(dataDir string) (*Store, error) {
	dir := filepath.Join(dataDir, "quarantine")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

type meta struct {
	ID        string            `json:"id"`
	From      string            `json:"from"`
	To        []string          `json:"to"`
	Subject   string            `json:"subject"`
	RemoteIP  string            `json:"remote_ip"`
	Reason    string            `json:"reason"`
	Action    string            `json:"action"`
	Score     float64           `json:"score,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// Put stores a quarantined or held message and returns its id.
func (s *Store) Put(msg *mailmsg.Message, data []byte, res *mailmsg.Result) (string, error) {
	id := msg.ID
	if id == "" {
		id = fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}
	m := meta{
		ID:        id,
		From:      msg.From,
		To:        append([]string{}, msg.To...),
		Subject:   msg.Subject,
		RemoteIP:  msg.RemoteIP,
		CreatedAt: time.Now().UTC(),
	}
	if res != nil {
		m.Reason = res.Reason
		m.Action = res.Action
		m.Score = res.Score
		m.Tags = append([]string{}, res.Tags...)
		m.Details = res.Details
	}
	base := filepath.Join(s.dir, id)
	if err := os.WriteFile(base+".eml", data, 0o640); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(base+".json", b, 0o640); err != nil {
		return "", err
	}
	return id, nil
}

// Dir returns the quarantine directory.
func (s *Store) Dir() string { return s.dir }
