package queue

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rkislov/mailedge/internal/mailmsg"
)

// Spool is a disk-backed mail queue with sidecar JSON metadata.
type Spool struct {
	root string
	log  *slog.Logger
	mu   sync.Mutex
}

// New creates a spool rooted at root/spool/{incoming,active,deferred,bounce}.
func New(dataDir string, log *slog.Logger) (*Spool, error) {
	if log == nil {
		log = slog.Default()
	}
	root := filepath.Join(dataDir, "spool")
	for _, dir := range []string{"incoming", "active", "deferred", "bounce"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			return nil, fmt.Errorf("create spool dir %s: %w", dir, err)
		}
	}
	return &Spool{root: root, log: log}, nil
}

// Root returns the spool root directory.
func (s *Spool) Root() string { return s.root }

// Enqueue writes message data and metadata into the incoming directory.
func (s *Spool) Enqueue(msg *mailmsg.Message, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if msg.ID == "" {
		msg.ID = newID()
	}
	if msg.ReceivedAt.IsZero() {
		msg.ReceivedAt = time.Now().UTC()
	}
	msg.State = mailmsg.StateIncoming
	msg.Size = int64(len(data))
	msg.NextAttempt = time.Now().UTC()

	dataPath := filepath.Join(s.root, "incoming", msg.ID+".eml")
	metaPath := filepath.Join(s.root, "incoming", msg.ID+".json")
	msg.DataPath = dataPath
	msg.MetaPath = metaPath

	tmpData := dataPath + ".tmp"
	if err := os.WriteFile(tmpData, data, 0o640); err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	if err := writeMeta(metaPath+".tmp", msg); err != nil {
		_ = os.Remove(tmpData)
		return err
	}
	if err := os.Rename(tmpData, dataPath); err != nil {
		_ = os.Remove(tmpData)
		_ = os.Remove(metaPath + ".tmp")
		return err
	}
	if err := os.Rename(metaPath+".tmp", metaPath); err != nil {
		_ = os.Remove(dataPath)
		_ = os.Remove(metaPath + ".tmp")
		return err
	}
	s.log.Info("enqueued", "id", msg.ID, "from", msg.From, "to", msg.To, "size", msg.Size)
	return nil
}

// ClaimReady moves due messages from incoming/deferred into active and returns them.
func (s *Spool) ClaimReady(limit int) ([]*mailmsg.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var out []*mailmsg.Message

	for _, state := range []mailmsg.State{mailmsg.StateIncoming, mailmsg.StateDeferred} {
		msgs, err := s.listState(state)
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if limit > 0 && len(out) >= limit {
				return out, nil
			}
			if state == mailmsg.StateDeferred && m.NextAttempt.After(now) {
				continue
			}
			claimed, err := s.moveLocked(m, mailmsg.StateActive)
			if err != nil {
				s.log.Warn("claim failed", "id", m.ID, "err", err)
				continue
			}
			out = append(out, claimed)
		}
	}
	return out, nil
}

// Defer marks a message for retry with exponential backoff.
func (s *Spool) Defer(msg *mailmsg.Message, reason string, initial, max time.Duration, maxAttempts int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	msg.Attempts++
	msg.LastError = reason
	if msg.Attempts >= maxAttempts {
		_, err := s.moveLocked(msg, mailmsg.StateBounce)
		return err
	}
	backoff := initial
	for i := 1; i < msg.Attempts; i++ {
		backoff *= 2
		if backoff > max {
			backoff = max
			break
		}
	}
	msg.NextAttempt = time.Now().UTC().Add(backoff)
	msg.State = mailmsg.StateDeferred
	if _, err := s.moveLocked(msg, mailmsg.StateDeferred); err != nil {
		return err
	}
	s.log.Info("deferred", "id", msg.ID, "attempts", msg.Attempts, "next", msg.NextAttempt, "reason", reason)
	return nil
}

// Complete removes a successfully delivered message from the spool.
func (s *Spool) Complete(msg *mailmsg.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.Remove(msg.DataPath)
	_ = os.Remove(msg.MetaPath)
	s.log.Info("delivered", "id", msg.ID, "attempts", msg.Attempts)
	return nil
}

// Bounce moves a message to the bounce directory.
func (s *Spool) Bounce(msg *mailmsg.Message, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	msg.LastError = reason
	if _, err := s.moveLocked(msg, mailmsg.StateBounce); err != nil {
		return err
	}
	s.log.Info("bounced", "id", msg.ID, "reason", reason)
	return nil
}

// RecoverActive moves leftover active messages back to deferred on startup.
func (s *Spool) RecoverActive() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	msgs, err := s.listState(mailmsg.StateActive)
	if err != nil {
		return 0, err
	}
	for _, m := range msgs {
		m.LastError = "recovered after restart"
		m.NextAttempt = time.Now().UTC()
		if _, err := s.moveLocked(m, mailmsg.StateDeferred); err != nil {
			return 0, err
		}
	}
	return len(msgs), nil
}

// Stats returns counts per spool state.
func (s *Spool) Stats() (map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, state := range []mailmsg.State{
		mailmsg.StateIncoming, mailmsg.StateActive, mailmsg.StateDeferred, mailmsg.StateBounce,
	} {
		msgs, err := s.listState(state)
		if err != nil {
			return nil, err
		}
		out[string(state)] = len(msgs)
	}
	return out, nil
}

func (s *Spool) listState(state mailmsg.State) ([]*mailmsg.Message, error) {
	dir := filepath.Join(s.root, string(state))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var msgs []*mailmsg.Message
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		m, err := readMeta(filepath.Join(dir, e.Name()))
		if err != nil {
			s.log.Warn("skip bad meta", "path", e.Name(), "err", err)
			continue
		}
		msgs = append(msgs, m)
	}
	return msgs, nil
}

func (s *Spool) moveLocked(msg *mailmsg.Message, to mailmsg.State) (*mailmsg.Message, error) {
	newData := filepath.Join(s.root, string(to), msg.ID+".eml")
	newMeta := filepath.Join(s.root, string(to), msg.ID+".json")

	if msg.DataPath != newData {
		if err := os.Rename(msg.DataPath, newData); err != nil {
			return nil, fmt.Errorf("move data: %w", err)
		}
	}
	msg.State = to
	msg.DataPath = newData
	msg.MetaPath = newMeta
	if err := writeMeta(newMeta, msg); err != nil {
		return nil, err
	}
	// Remove old meta if it lived elsewhere.
	oldMetaCandidates := []string{
		filepath.Join(s.root, "incoming", msg.ID+".json"),
		filepath.Join(s.root, "active", msg.ID+".json"),
		filepath.Join(s.root, "deferred", msg.ID+".json"),
		filepath.Join(s.root, "bounce", msg.ID+".json"),
	}
	for _, p := range oldMetaCandidates {
		if p != newMeta {
			_ = os.Remove(p)
		}
	}
	return msg, nil
}

// ReadData returns the raw message bytes.
func (s *Spool) ReadData(msg *mailmsg.Message) ([]byte, error) {
	return os.ReadFile(msg.DataPath)
}

func writeMeta(path string, msg *mailmsg.Message) error {
	b, err := json.MarshalIndent(msg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readMeta(path string) (*mailmsg.Message, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m mailmsg.Message
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func newID() string {
	return fmt.Sprintf("%d.%d", time.Now().UnixNano(), os.Getpid())
}
