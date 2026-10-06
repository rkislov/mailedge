package auth

import "testing"

func TestHashAndCheck(t *testing.T) {
	h, err := HashPassword("secret123")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "secret123") {
		t.Fatalf("check failed for %q", h)
	}
	if CheckPassword(h, "wrong") {
		t.Fatal("accepted wrong password")
	}
}
