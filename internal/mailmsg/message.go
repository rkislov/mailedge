package mailmsg

import (
	"time"
)

// State is the queue lifecycle state of a message.
type State string

const (
	StateIncoming State = "incoming"
	StateActive   State = "active"
	StateDeferred State = "deferred"
	StateBounce   State = "bounce"
	StateDone     State = "done"
)

// Message holds envelope and metadata for a queued mail item.
type Message struct {
	ID          string    `json:"id"`
	From        string    `json:"from"`
	To          []string  `json:"to"`
	RemoteIP    string    `json:"remote_ip"`
	Helo        string    `json:"helo"`
	ReceivedAt  time.Time `json:"received_at"`
	State       State     `json:"state"`
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"next_attempt"`
	LastError   string    `json:"last_error,omitempty"`
	Size        int64     `json:"size"`
	Subject     string    `json:"subject,omitempty"`
	DataPath    string    `json:"data_path"`
	MetaPath    string    `json:"meta_path"`
}

// Result is the outcome of a filter or policy evaluation.
type Result struct {
	Action         string            `json:"action"` // accept, reject, quarantine, discard, tag, hold
	Score          float64           `json:"score,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	Details        map[string]string `json:"details,omitempty"`
	PrependHeaders []string          `json:"-"` // "Name: value" lines to prepend
}

