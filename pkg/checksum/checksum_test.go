package checksum

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSHA256KnownVector(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.txt")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Well-known SHA-256 of "abc".
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	got, err := FileSHA256(path)
	if err != nil {
		t.Fatalf("FileSHA256() error = %v", err)
	}
	if got != want {
		t.Errorf("FileSHA256() = %q, want %q", got, want)
	}
}

func TestHasherFileSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.bin")
	content := []byte("hello go-ti\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])

	got, err := (Hasher{}).FileSHA256(path)
	if err != nil {
		t.Fatalf("Hasher.FileSHA256() error = %v", err)
	}
	if got != want {
		t.Errorf("Hasher.FileSHA256() = %q, want %q", got, want)
	}
}

func TestFileSHA256MissingFile(t *testing.T) {
	_, err := FileSHA256(filepath.Join(t.TempDir(), "missing.txt"))
	if err == nil {
		t.Fatal("FileSHA256() on missing file: expected error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want it to wrap os.ErrNotExist", err)
	}
}
