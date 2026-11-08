package secrets

import "testing"

func TestRoundTrip(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(k)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := c.Encrypt("sk-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(enc) {
		t.Fatalf("missing prefix: %s", enc)
	}
	got, err := c.Decrypt(enc)
	if err != nil || got != "sk-secret" {
		t.Fatalf("got %q, %v", got, err)
	}

	other, _ := GenerateKey()
	c2, _ := New(other)
	if _, err := c2.Decrypt(enc); err == nil {
		t.Fatal("decrypt with wrong key succeeded")
	}
	if _, err := New("dG9vc2hvcnQ="); err == nil {
		t.Fatal("short key accepted")
	}
}
