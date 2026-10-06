package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/rkislov/mailedge/internal/mailmsg"
)

// Storage is the portable data-access layer (SQLite/PostgreSQL in later stages).
type Storage interface {
	Messages() MessageRepo
	Queue() QueueRepo
	Quarantine() QuarantineRepo
	IOC() IOCRepo
	DKIM() DKIMRepo
	Policies() PolicyRepo
	Users() UserRepo
	Audit() AuditRepo
	Stats() StatsRepo
	Migrate(ctx context.Context) error
	Close() error
}

type MessageRepo interface {
	Save(ctx context.Context, msg *mailmsg.Message) error
	Get(ctx context.Context, id string) (*mailmsg.Message, error)
}

type QueueRepo interface {
	List(ctx context.Context) ([]*mailmsg.Message, error)
}

type QuarantineRepo interface {
	List(ctx context.Context) ([]*mailmsg.Message, error)
}

type IOCRepo interface {
	Lookup(ctx context.Context, value string) (bool, error)
}

type DKIMRepo interface {
	List(ctx context.Context) ([]string, error)
}

type PolicyRepo interface {
	List(ctx context.Context) ([]string, error)
}

type UserRepo interface {
	List(ctx context.Context) ([]string, error)
}

type AuditRepo interface {
	Append(ctx context.Context, action string) error
}

type StatsRepo interface {
	Increment(ctx context.Context, key string, n int64) error
}

// Memory is an in-memory stub for Stage 1.
type Memory struct {
	mu   sync.RWMutex
	msgs map[string]*mailmsg.Message
}

// OpenMemory returns a memory-backed storage.
func OpenMemory() *Memory {
	return &Memory{msgs: make(map[string]*mailmsg.Message)}
}

func (m *Memory) Messages() MessageRepo     { return m }
func (m *Memory) Queue() QueueRepo          { return &noopQueue{} }
func (m *Memory) Quarantine() QuarantineRepo { return &noopQuarantine{} }
func (m *Memory) IOC() IOCRepo              { return &noopIOC{} }
func (m *Memory) DKIM() DKIMRepo            { return &noopDKIM{} }
func (m *Memory) Policies() PolicyRepo      { return &noopPolicies{} }
func (m *Memory) Users() UserRepo           { return &noopUsers{} }
func (m *Memory) Audit() AuditRepo          { return &noopAudit{} }
func (m *Memory) Stats() StatsRepo          { return &noopStats{} }
func (m *Memory) Migrate(context.Context) error { return nil }
func (m *Memory) Close() error                  { return nil }

func (m *Memory) Save(_ context.Context, msg *mailmsg.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *msg
	m.msgs[msg.ID] = &cp
	return nil
}

func (m *Memory) Get(_ context.Context, id string) (*mailmsg.Message, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	msg, ok := m.msgs[id]
	if !ok {
		return nil, fmt.Errorf("message %s not found", id)
	}
	cp := *msg
	return &cp, nil
}

type noopQueue struct{}

func (noopQueue) List(context.Context) ([]*mailmsg.Message, error) { return nil, nil }

type noopQuarantine struct{}

func (noopQuarantine) List(context.Context) ([]*mailmsg.Message, error) { return nil, nil }

type noopIOC struct{}

func (noopIOC) Lookup(context.Context, string) (bool, error) { return false, nil }

type noopDKIM struct{}

func (noopDKIM) List(context.Context) ([]string, error) { return nil, nil }

type noopPolicies struct{}

func (noopPolicies) List(context.Context) ([]string, error) { return nil, nil }

type noopUsers struct{}

func (noopUsers) List(context.Context) ([]string, error) { return nil, nil }

type noopAudit struct{}

func (noopAudit) Append(context.Context, string) error { return nil }

type noopStats struct{}

func (noopStats) Increment(context.Context, string, int64) error { return nil }

// Open selects a storage backend. Stage 1 always returns Memory; disk spool is separate.
func Open(driver string) (Storage, error) {
	switch driver {
	case "", "sqlite", "postgres", "memory":
		return OpenMemory(), nil
	default:
		return nil, fmt.Errorf("unsupported storage driver: %s", driver)
	}
}
