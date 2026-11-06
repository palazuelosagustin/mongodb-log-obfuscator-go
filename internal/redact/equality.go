package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// With an equality key, redacted strings become a keyed hash instead of one
// shared placeholder: equal values stay equal, so repeated values (hot keys,
// skewed filters) remain visible. Without the key, which only the mapping
// holds, the hashes cannot be tested against guessed values.
var (
	equalityMu  sync.RWMutex
	equalityKey []byte
)

// SetEqualityKey enables (non-nil) or disables (nil) keyed hashes.
func SetEqualityKey(key []byte) {
	equalityMu.Lock()
	defer equalityMu.Unlock()
	equalityKey = key
}

// Token is the replacement of a redacted string value.
func Token(value string) string {
	equalityMu.RLock()
	key := equalityKey
	equalityMu.RUnlock()
	if key == nil {
		return StringPlaceholder
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return "obf_" + hex.EncodeToString(mac.Sum(nil))[:12]
}
