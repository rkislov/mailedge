package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrNoUsers            = errors.New("no users")
	ErrUserExists         = errors.New("user exists")
)

// Service handles password hashing and sessions.
type Service struct {
	db *sql.DB
}

func New(db *sql.DB) *Service {
	return &Service{db: db}
}

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
}

type Session struct {
	Token     string
	UserID    int64
	CSRFToken string
	ExpiresAt time.Time
	Username  string
	Role      string
}

func (s *Service) HasUsers(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&n)
	return n > 0, err
}

func (s *Service) CreateAdmin(ctx context.Context, username, password string) error {
	ok, err := s.HasUsers(ctx)
	if err != nil {
		return err
	}
	if ok {
		return ErrUserExists
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)`,
		username, hash, "admin", now)
	return err
}

func (s *Service) Authenticate(ctx context.Context, username, password string) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if !CheckPassword(u.PasswordHash, password) {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

func (s *Service) CreateSession(ctx context.Context, userID int64, ttl time.Duration) (*Session, error) {
	token, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	exp := time.Now().UTC().Add(ttl)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions(token, user_id, csrf_token, expires_at, created_at) VALUES(?,?,?,?,?)`,
		token, userID, csrf, exp.Format(time.RFC3339), now)
	if err != nil {
		return nil, err
	}
	return &Session{Token: token, UserID: userID, CSRFToken: csrf, ExpiresAt: exp}, nil
}

func (s *Service) GetSession(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, sql.ErrNoRows
	}
	sess := &Session{Token: token}
	var exp string
	err := s.db.QueryRowContext(ctx, `
		SELECT s.user_id, s.csrf_token, s.expires_at, u.username, u.role
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token=?`, token).
		Scan(&sess.UserID, &sess.CSRFToken, &exp, &sess.Username, &sess.Role)
	if err != nil {
		return nil, err
	}
	sess.ExpiresAt, err = time.Parse(time.RFC3339, exp)
	if err != nil {
		return nil, err
	}
	if time.Now().UTC().After(sess.ExpiresAt) {
		_ = s.DeleteSession(ctx, token)
		return nil, sql.ErrNoRows
	}
	return sess, nil
}

func (s *Service) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token=?`, token)
	return err
}

// HashPassword uses argon2id.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return fmt.Sprintf("argon2id$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func CheckPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	if len(got) != len(want) {
		return false
	}
	var v byte
	for i := range got {
		v |= got[i] ^ want[i]
	}
	return v == 0
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
