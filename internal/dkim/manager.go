package dkimkeys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

type Key struct {
	ID           int64
	Domain       string
	Selector     string
	Algorithm    string
	PublicPEM    string
	PrivatePath  string
	SignOutbound bool
	Enabled      bool
	CreatedAt    string
}

type Manager struct {
	db     *sql.DB
	keysDir string
}

func New(db *sql.DB, dataDir string) (*Manager, error) {
	dir := filepath.Join(dataDir, "dkim")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &Manager{db: db, keysDir: dir}, nil
}

func (m *Manager) List(ctx context.Context) ([]Key, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT id, domain, selector, algorithm, public_pem, private_path, sign_outbound, enabled, created_at
		FROM dkim_keys ORDER BY domain, selector`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		var k Key
		var sign, en int
		if err := rows.Scan(&k.ID, &k.Domain, &k.Selector, &k.Algorithm, &k.PublicPEM, &k.PrivatePath, &sign, &en, &k.CreatedAt); err != nil {
			return nil, err
		}
		k.SignOutbound = sign == 1
		k.Enabled = en == 1
		out = append(out, k)
	}
	return out, rows.Err()
}

func (m *Manager) Generate(ctx context.Context, domain, selector, algo string, signOutbound bool) (*Key, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	selector = strings.TrimSpace(selector)
	if selector == "" {
		selector = "mgw"
	}
	if algo == "" {
		algo = "rsa2048"
	}

	var priv any
	var pubPEM []byte
	var err error
	switch strings.ToLower(algo) {
	case "rsa2048":
		priv, pubPEM, err = genRSA(2048)
	case "rsa4096":
		priv, pubPEM, err = genRSA(4096)
	case "ed25519":
		priv, pubPEM, err = genEd25519()
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", algo)
	}
	if err != nil {
		return nil, err
	}

	privPEM, err := marshalPrivate(priv)
	if err != nil {
		return nil, err
	}
	fname := fmt.Sprintf("%s.%s.pem", domain, selector)
	path := filepath.Join(m.keysDir, fname)
	if err := os.WriteFile(path, privPEM, 0o600); err != nil {
		return nil, err
	}

	sign := 0
	if signOutbound {
		sign = 1
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := m.db.ExecContext(ctx, `
		INSERT INTO dkim_keys(domain, selector, algorithm, public_pem, private_path, sign_outbound, enabled, created_at)
		VALUES(?,?,?,?,?,?,1,?)
		ON CONFLICT(domain, selector) DO UPDATE SET
			algorithm=excluded.algorithm,
			public_pem=excluded.public_pem,
			private_path=excluded.private_path,
			sign_outbound=excluded.sign_outbound,
			enabled=1`,
		domain, selector, algo, string(pubPEM), path, sign, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Key{
		ID: id, Domain: domain, Selector: selector, Algorithm: algo,
		PublicPEM: string(pubPEM), PrivatePath: path, SignOutbound: signOutbound, Enabled: true, CreatedAt: now,
	}, nil
}

func (m *Manager) Delete(ctx context.Context, id int64) error {
	var path string
	_ = m.db.QueryRowContext(ctx, `SELECT private_path FROM dkim_keys WHERE id=?`, id).Scan(&path)
	_, err := m.db.ExecContext(ctx, `DELETE FROM dkim_keys WHERE id=?`, id)
	if path != "" {
		_ = os.Remove(path)
	}
	return err
}

func (m *Manager) DNSRecord(k Key) string {
	pub := extractPublicKeyBytes(k.PublicPEM)
	b64 := base64.StdEncoding.EncodeToString(pub)
	kt := "rsa"
	if strings.EqualFold(k.Algorithm, "ed25519") {
		kt = "ed25519"
	}
	return fmt.Sprintf("%s._domainkey.%s. IN TXT \"v=DKIM1; k=%s; p=%s\"", k.Selector, k.Domain, kt, b64)
}

func (m *Manager) Sign(msg []byte, fromDomain string) ([]byte, error) {
	ctx := context.Background()
	var k Key
	var sign, en int
	err := m.db.QueryRowContext(ctx, `
		SELECT id, domain, selector, algorithm, public_pem, private_path, sign_outbound, enabled, created_at
		FROM dkim_keys WHERE domain=? AND enabled=1 AND sign_outbound=1
		ORDER BY id DESC LIMIT 1`, strings.ToLower(fromDomain)).
		Scan(&k.ID, &k.Domain, &k.Selector, &k.Algorithm, &k.PublicPEM, &k.PrivatePath, &sign, &en, &k.CreatedAt)
	if err == sql.ErrNoRows {
		return msg, nil
	}
	if err != nil {
		return nil, err
	}
	privPEM, err := os.ReadFile(k.PrivatePath)
	if err != nil {
		return nil, err
	}
	priv, err := parsePrivate(privPEM)
	if err != nil {
		return nil, err
	}
	opts := &dkim.SignOptions{
		Domain:   k.Domain,
		Selector: k.Selector,
		Signer:   priv.(crypto.Signer),
	}
	var buf strings.Builder
	if err := dkim.Sign(&buf, strings.NewReader(string(msg)), opts); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func genRSA(bits int) (any, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), nil
}

func genEd25519() (any, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	return priv, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), nil
}

func marshalPrivate(priv any) ([]byte, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), nil
	case ed25519.PrivateKey:
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
	default:
		b, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
	}
}

func parsePrivate(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		_ = elliptic.P256()
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key")
}

func extractPublicKeyBytes(pubPEM string) []byte {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return block.Bytes
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return x509.MarshalPKCS1PublicKey(k)
	case ed25519.PublicKey:
		return []byte(k)
	default:
		b, _ := x509.MarshalPKIXPublicKey(pub)
		return b
	}
}
