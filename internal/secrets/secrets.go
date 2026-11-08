// Package secrets encrypts and decrypts provider credentials with AES-256-GCM.
//
// Encrypted values are stored in the config as "enc:v1:<base64(nonce||ciphertext)>".
// The master key is 32 random bytes, exchanged as standard base64.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const Prefix = "enc:v1:"

// CheckPrefix marks a master key check value ("kcv:v1:<hex>").
const CheckPrefix = "kcv:v1:"

const kcvLabel = "simple-router master key check v1"

// KeySize is the master key length in bytes (AES-256).
const KeySize = 32

// ErrDecrypt means a well-formed value failed authentication: wrong key or tampering.
var ErrDecrypt = errors.New("decryption failed (wrong master key or corrupted value)")

// GenerateKey returns a new random master key, base64 encoded.
func GenerateKey() (string, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k), nil
}

// Cipher encrypts and decrypts secrets with a master key.
type Cipher struct {
	aead cipher.AEAD
	kcv  string
}

// New parses a base64 master key and returns a Cipher.
func New(masterKey string) (*Cipher, error) {
	masterKey = strings.TrimSpace(masterKey)
	if masterKey == "" {
		return nil, errors.New("master key is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(masterKey)
	if err != nil {
		return nil, fmt.Errorf("master key is not valid base64: %w", err)
	}
	if len(raw) != KeySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", KeySize, len(raw))
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte(kcvLabel))
	return &Cipher{aead: aead, kcv: CheckPrefix + hex.EncodeToString(mac.Sum(nil)[:16])}, nil
}

// Encrypt returns the "enc:v1:..." form of plaintext.
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := c.aead.Seal(nonce, nonce, []byte(plaintext), []byte(Prefix))
	return Prefix + base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt reverses Encrypt. It fails if the value is not encrypted or the key is wrong.
func (c *Cipher) Decrypt(value string) (string, error) {
	if !IsEncrypted(value) {
		return "", errors.New("value is not encrypted (expected enc:v1: prefix)")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, Prefix))
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext encoding: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns+c.aead.Overhead() {
		return "", errors.New("ciphertext too short")
	}
	pt, err := c.aead.Open(nil, raw[:ns], raw[ns:], []byte(Prefix))
	if err != nil {
		return "", ErrDecrypt
	}
	return string(pt), nil
}

// KeyCheck returns a value that identifies the master key without revealing it:
// HMAC-SHA256(key, fixed label), truncated to 128 bits. Store it in the config
// as master_key_check so a wrong key is detected before anything is encrypted.
func (c *Cipher) KeyCheck() string { return c.kcv }

// VerifyKeyCheck reports whether check was produced by this master key.
func (c *Cipher) VerifyKeyCheck(check string) bool {
	return subtle.ConstantTimeCompare([]byte(check), []byte(c.kcv)) == 1
}

// IsEncrypted reports whether value carries the encrypted prefix.
func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, Prefix)
}
