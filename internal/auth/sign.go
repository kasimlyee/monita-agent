// Package auth implements per-request signing per PROTOCOL.md §2.3.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// Headers returns the four auth headers required on every metrics/logs push.
// signingKey is base64url-encoded (as provisioned and stored in config).
func Headers(token, signingKeyB64url, fingerprintHash string, body []byte) (map[string]string, error) {
	key, err := base64.URLEncoding.DecodeString(signingKeyB64url)
	if err != nil {
		// tolerate no-padding variant
		key, err = base64.RawURLEncoding.DecodeString(signingKeyB64url)
		if err != nil {
			return nil, fmt.Errorf("decode signing key: %w", err)
		}
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)

	var nonceBuf [16]byte
	if _, err := rand.Read(nonceBuf[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBuf[:])

	sig := sign(key, ts, nonce, fingerprintHash, body)

	return map[string]string{
		"Authorization": "Bearer " + token,
		"X-Timestamp":   ts,
		"X-Nonce":       nonce,
		"X-Signature":   sig,
	}, nil
}

// sign computes HMAC-SHA256 over the canonical signed material per PROTOCOL.md §2.3:
//
//	timestamp + "." + nonce + "." + fingerprint_hash + "." + hex(sha256(body))
func sign(key []byte, timestamp, nonce, fingerprintHash string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	material := timestamp + "." + nonce + "." + fingerprintHash + "." + hex.EncodeToString(bodyHash[:])

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(material))
	return hex.EncodeToString(mac.Sum(nil))
}