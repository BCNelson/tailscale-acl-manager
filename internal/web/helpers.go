package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/google/uuid"
)

// generateID generates a new UUID.
func generateID() string {
	return uuid.New().String()
}

// generateAPIKeyPair generates a new API key with its hash and prefix.
func generateAPIKeyPair() (key string, hash string, prefix string, err error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", "", err
	}

	key = "acl_" + hex.EncodeToString(bytes)
	h := sha256.Sum256([]byte(key))
	hash = hex.EncodeToString(h[:])
	prefix = key[:12] // "acl_" + first 8 chars of hex

	return key, hash, prefix, nil
}

// parseInt parses a string to int with a default value.
func parseInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}
