// Package auth authenticates client API keys and enforces per-key model access.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"

	"github.com/gstos/SimpleLLMRouter/internal/config"
)

// KeyPrefix is prepended to generated client keys.
const KeyPrefix = "sr-"

// Key is an authenticated client.
type Key struct {
	Name      string
	Admin     bool
	models    []string // nil => all models
	providers []string // /provider/<name>/ access; nil => none
}

// AllowsProvider reports whether the key may reach provider directly at
// /provider/<name>/ (auth: managed providers). Default: none.
func (k *Key) AllowsProvider(name string) bool {
	for _, pat := range k.providers {
		if ok, _ := path.Match(pat, name); ok {
			return true
		}
	}
	return false
}

// Allows reports whether the key may use model.
func (k *Key) Allows(model string) bool {
	if k.models == nil {
		return true
	}
	for _, pat := range k.models {
		if ok, _ := path.Match(pat, model); ok {
			return true
		}
	}
	return false
}

// Store looks up keys by hash.
type Store struct {
	byHash map[[32]byte]*Key
}

func NewStore(keys []config.APIKey) *Store {
	s := &Store{byHash: map[[32]byte]*Key{}}
	for _, k := range keys {
		raw, err := hex.DecodeString(strings.TrimPrefix(k.Hash, "sha256:"))
		if err != nil || len(raw) != 32 {
			continue // rejected by config validation
		}
		key := &Key{Name: k.Name, Admin: k.Admin, providers: k.Providers}
		for _, m := range k.Models {
			if m == "*" {
				key.models = nil
				break
			}
			key.models = append(key.models, m)
		}
		var h [32]byte
		copy(h[:], raw)
		s.byHash[h] = key
	}
	return s
}

// Lookup returns the key matching the plaintext token, or nil.
func (s *Store) Lookup(token string) *Key {
	if token == "" {
		return nil
	}
	// Lookup is by SHA-256 of the token, so timing reveals nothing about stored keys.
	return s.byHash[sha256.Sum256([]byte(token))]
}

// Hash returns the config form ("sha256:<hex>") of a client key.
func Hash(token string) string {
	h := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(h[:])
}

// GenerateKey returns a new random client key.
func GenerateKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return KeyPrefix + hex.EncodeToString(b), nil
}
