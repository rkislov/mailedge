package intel

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Indicator types.
const (
	TypeIP     = "ip"
	TypeDomain = "domain"
	TypeURL    = "url"
	TypeHash   = "hash"
)

// IOC is one indicator of compromise.
type IOC struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Threat    string `json:"threat"`
	Source    string `json:"source"`
	Action    string `json:"action,omitempty"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// Store persists IOCs in SQLite.
type Store struct {
	db *sql.DB
}

// NewStore wraps a database connection.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// NormalizeType maps feed-specific types to ip|domain|url|hash.
func NormalizeType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	switch {
	case t == "ip" || strings.HasPrefix(t, "ip:"):
		return TypeIP
	case t == "domain" || t == "hostname":
		return TypeDomain
	case t == "url" || t == "uri":
		return TypeURL
	case strings.Contains(t, "hash") || t == "md5" || t == "sha1" || t == "sha256" || t == "hash":
		return TypeHash
	default:
		return t
	}
}

// NormalizeValue cleans IOC values.
func NormalizeValue(typ, value string) string {
	value = strings.TrimSpace(value)
	switch typ {
	case TypeIP:
		if host, _, err := net.SplitHostPort(value); err == nil {
			return host
		}
		if i := strings.LastIndex(value, ":"); i > 0 {
			if ip := net.ParseIP(value[:i]); ip != nil {
				return value[:i]
			}
		}
		return value
	case TypeDomain:
		return strings.ToLower(strings.TrimSuffix(value, "."))
	case TypeHash:
		return strings.ToLower(value)
	default:
		return value
	}
}

// Upsert inserts or updates an IOC (new rows are enabled).
func (s *Store) Upsert(ctx context.Context, ioc IOC) (int64, error) {
	typ := NormalizeType(ioc.Type)
	val := NormalizeValue(typ, ioc.Value)
	if typ == "" || val == "" {
		return 0, fmt.Errorf("ioc type and value required")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	src := ioc.Source
	if src == "" {
		src = "manual"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO iocs(type, value, threat, source, action, enabled, created_at, updated_at)
		VALUES(?,?,?,?,?,1,?,?)
		ON CONFLICT(type, value) DO UPDATE SET
			threat=excluded.threat,
			source=CASE WHEN excluded.source='manual' THEN 'manual' ELSE excluded.source END,
			action=CASE WHEN excluded.action!='' THEN excluded.action ELSE iocs.action END,
			updated_at=excluded.updated_at
	`, typ, val, ioc.Threat, src, ioc.Action, now, now)
	if err != nil {
		return 0, err
	}
	var id int64
	_ = s.db.QueryRowContext(ctx, `SELECT id FROM iocs WHERE type=? AND value=?`, typ, val).Scan(&id)
	return id, nil
}

// BulkUpsert inserts many IOCs in a transaction.
func (s *Store) BulkUpsert(ctx context.Context, list []IOC) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO iocs(type, value, threat, source, action, enabled, created_at, updated_at)
		VALUES(?,?,?,?,?,1,?,?)
		ON CONFLICT(type, value) DO UPDATE SET
			threat=excluded.threat,
			source=CASE WHEN iocs.source='manual' THEN iocs.source ELSE excluded.source END,
			updated_at=excluded.updated_at
	`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	n := 0
	for _, ioc := range list {
		typ := NormalizeType(ioc.Type)
		val := NormalizeValue(typ, ioc.Value)
		if typ == "" || val == "" {
			continue
		}
		src := ioc.Source
		if src == "" {
			src = "feed"
		}
		if _, err := stmt.ExecContext(ctx, typ, val, ioc.Threat, src, ioc.Action, now, now); err != nil {
			return n, err
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return n, err
	}
	return n, nil
}

// Delete removes by id.
func (s *Store) Delete(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM iocs WHERE id=?`, id)
	return err
}

// SetEnabled toggles an IOC.
func (s *Store) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.db.ExecContext(ctx, `UPDATE iocs SET enabled=?, updated_at=? WHERE id=?`,
		en, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// Get looks up an enabled IOC by type+value.
func (s *Store) Get(ctx context.Context, typ, value string) (*IOC, error) {
	typ = NormalizeType(typ)
	value = NormalizeValue(typ, value)
	row := s.db.QueryRowContext(ctx, `
		SELECT id, type, value, threat, source, action, enabled, created_at, updated_at
		FROM iocs WHERE type=? AND value=? AND enabled=1`, typ, value)
	ioc, err := scanIOC(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return ioc, err
}

// LookupAny returns the first matching enabled IOC.
func (s *Store) LookupAny(ctx context.Context, candidates []IOC) (*IOC, error) {
	for _, c := range candidates {
		hit, err := s.Get(ctx, c.Type, c.Value)
		if err != nil {
			return nil, err
		}
		if hit != nil {
			return hit, nil
		}
	}
	return nil, nil
}

// List returns IOCs with optional filters.
func (s *Store) List(ctx context.Context, typ, source, q string, limit int) ([]IOC, error) {
	if limit <= 0 {
		limit = 200
	}
	query := `SELECT id, type, value, threat, source, action, enabled, created_at, updated_at FROM iocs WHERE 1=1`
	var args []any
	if typ != "" {
		query += ` AND type=?`
		args = append(args, NormalizeType(typ))
	}
	if source != "" {
		query += ` AND source=?`
		args = append(args, source)
	}
	if q != "" {
		query += ` AND (value LIKE ? OR threat LIKE ?)`
		like := "%" + q + "%"
		args = append(args, like, like)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IOC
	for rows.Next() {
		ioc, err := scanIOC(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ioc)
	}
	return out, rows.Err()
}

// Count returns total IOC rows.
func (s *Store) Count(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM iocs`).Scan(&n)
	return n, err
}

// StatsBySource returns counts grouped by source.
func (s *Store) StatsBySource(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source, COUNT(*) FROM iocs GROUP BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var src string
		var n int
		if err := rows.Scan(&src, &n); err != nil {
			return nil, err
		}
		out[src] = n
	}
	return out, rows.Err()
}

// ExportJSON writes all IOCs as JSON array.
func (s *Store) ExportJSON(ctx context.Context, w io.Writer) error {
	list, err := s.List(ctx, "", "", "", 100000)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(list)
}

// ImportJSON reads a JSON array of IOCs.
func (s *Store) ImportJSON(ctx context.Context, r io.Reader) (int, error) {
	var list []IOC
	if err := json.NewDecoder(r).Decode(&list); err != nil {
		return 0, err
	}
	for i := range list {
		if list[i].Source == "" {
			list[i].Source = "import"
		}
	}
	return s.BulkUpsert(ctx, list)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanIOC(row scanner) (*IOC, error) {
	var i IOC
	var en int
	err := row.Scan(&i.ID, &i.Type, &i.Value, &i.Threat, &i.Source, &i.Action, &en, &i.CreatedAt, &i.UpdatedAt)
	if err != nil {
		return nil, err
	}
	i.Enabled = en == 1
	return &i, nil
}
