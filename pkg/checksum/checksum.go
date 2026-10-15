// Package checksum provides file hashing utilities.
package checksum

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Hasher implements file hashing. It is safe for concurrent use.
type Hasher struct{}

// FileSHA256 returns the lowercase hex-encoded SHA-256 digest of the file at path.
func FileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer func() {
		// Closing a read-only file after a successful full read cannot fail
		// meaningfully; the discard is deliberate.
		_ = file.Close()
	}()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// FileSHA256 returns the lowercase hex-encoded SHA-256 digest of the file at path.
func (Hasher) FileSHA256(path string) (string, error) {
	return FileSHA256(path)
}
