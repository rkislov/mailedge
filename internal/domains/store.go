package domains

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type Domain struct {
	ID        int64
	Name      string
	AcceptMail bool
	CatchAll  string
	Enabled   bool
	CreatedAt string
}

type Route struct {
	ID        int64
	Domain    string
	NextHop   string
	Enabled   bool
	CreatedAt string
}

type Alias struct {
	ID           int64
	Address      string
	Destinations []string
	Enabled      bool
	CreatedAt    string
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) ListDomains(ctx context.Context) ([]Domain, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, accept_mail, catch_all, enabled, created_at FROM domains ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		var d Domain
		var accept, en int
		if err := rows.Scan(&d.ID, &d.Name, &accept, &d.CatchAll, &en, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.AcceptMail = accept == 1
		d.Enabled = en == 1
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) AddDomain(ctx context.Context, name, catchAll string, accept bool) error {
	name = strings.ToLower(strings.TrimSpace(name))
	now := time.Now().UTC().Format(time.RFC3339)
	acc := 0
	if accept {
		acc = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO domains(name, accept_mail, catch_all, enabled, created_at) VALUES(?,?,?,?,?)`,
		name, acc, strings.TrimSpace(catchAll), 1, now)
	return err
}

func (s *Store) DeleteDomain(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM domains WHERE id=?`, id)
	return err
}

func (s *Store) AcceptsDomain(ctx context.Context, domain string) (bool, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM domains`).Scan(&n)
	if err != nil {
		return false, err
	}
	if n == 0 {
		return true, nil // empty list = accept all (dev-friendly)
	}
	var en, accept int
	err = s.db.QueryRowContext(ctx,
		`SELECT enabled, accept_mail FROM domains WHERE name=?`, domain).Scan(&en, &accept)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return en == 1 && accept == 1, nil
}

func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, domain, next_hop, enabled, created_at FROM routes ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Route
	for rows.Next() {
		var r Route
		var en int
		if err := rows.Scan(&r.ID, &r.Domain, &r.NextHop, &en, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AddRoute(ctx context.Context, domain, nextHop string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO routes(domain, next_hop, enabled, created_at) VALUES(?,?,1,?)
		 ON CONFLICT(domain) DO UPDATE SET next_hop=excluded.next_hop, enabled=1`,
		strings.ToLower(strings.TrimSpace(domain)), strings.TrimSpace(nextHop), now)
	return err
}

func (s *Store) DeleteRoute(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM routes WHERE id=?`, id)
	return err
}

func (s *Store) NextHop(ctx context.Context, domain string) (string, bool, error) {
	var hop string
	var en int
	err := s.db.QueryRowContext(ctx,
		`SELECT next_hop, enabled FROM routes WHERE domain=?`, strings.ToLower(domain)).
		Scan(&hop, &en)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return hop, en == 1, nil
}

func (s *Store) ListAliases(ctx context.Context) ([]Alias, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, address, destinations, enabled, created_at FROM aliases ORDER BY address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alias
	for rows.Next() {
		var a Alias
		var dest string
		var en int
		if err := rows.Scan(&a.ID, &a.Address, &dest, &en, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Destinations = splitDest(dest)
		a.Enabled = en == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) AddAlias(ctx context.Context, address, destinations string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO aliases(address, destinations, enabled, created_at) VALUES(?,?,1,?)
		 ON CONFLICT(address) DO UPDATE SET destinations=excluded.destinations, enabled=1`,
		strings.ToLower(strings.TrimSpace(address)), strings.TrimSpace(destinations), now)
	return err
}

func (s *Store) DeleteAlias(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM aliases WHERE id=?`, id)
	return err
}

func (s *Store) ExpandAlias(ctx context.Context, address string) ([]string, bool, error) {
	var dest string
	var en int
	err := s.db.QueryRowContext(ctx,
		`SELECT destinations, enabled FROM aliases WHERE address=?`, strings.ToLower(address)).
		Scan(&dest, &en)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if en != 1 {
		return nil, false, nil
	}
	return splitDest(dest), true, nil
}

func splitDest(s string) []string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func DomainOf(addr string) string {
	addr = strings.Trim(addr, "<>")
	i := strings.LastIndex(addr, "@")
	if i < 0 || i == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[i+1:])
}
