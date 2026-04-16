package ctap2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// KnownHandles tracks hashes of credential handles we have successfully
// signed with, so that multi-entry allowList requests can skip the expensive
// probe-sign step and go straight to the handle we already know is ours.
//
// Hashes are SHA-256 of the raw handle bytes. Storage is a JSON array of
// hex-encoded hashes at ~/.config/linux-id/known-handles.json.
type KnownHandles struct {
	mu    sync.Mutex
	path  string
	known map[[32]byte]struct{}
}

// NewKnownHandles returns a KnownHandles backed by ~/.config/linux-id/known-handles.json.
func NewKnownHandles() *KnownHandles {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	kh := &KnownHandles{
		path:  filepath.Join(home, ".config", "linux-id", "known-handles.json"),
		known: make(map[[32]byte]struct{}),
	}
	kh.load()
	return kh
}

func (kh *KnownHandles) load() {
	data, err := os.ReadFile(kh.path)
	if err != nil {
		return
	}
	var entries []string
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}
	for _, s := range entries {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			continue
		}
		var h [32]byte
		copy(h[:], b)
		kh.known[h] = struct{}{}
	}
}

func (kh *KnownHandles) persist() error {
	entries := make([]string, 0, len(kh.known))
	for h := range kh.known {
		entries = append(entries, hex.EncodeToString(h[:]))
	}
	if err := os.MkdirAll(filepath.Dir(kh.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := kh.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, kh.path)
}

// Contains reports whether handle has been seen before. A nil receiver
// always returns false, letting callers leave KnownHandles unset (e.g. in
// tests) without panicking.
func (kh *KnownHandles) Contains(handle []byte) bool {
	if kh == nil {
		return false
	}
	h := sha256.Sum256(handle)
	kh.mu.Lock()
	defer kh.mu.Unlock()
	_, ok := kh.known[h]
	return ok
}

// Add records handle as known and persists the updated set.
// Does nothing if handle is already known or the receiver is nil.
func (kh *KnownHandles) Add(handle []byte) {
	if kh == nil {
		return
	}
	h := sha256.Sum256(handle)
	kh.mu.Lock()
	if _, ok := kh.known[h]; ok {
		kh.mu.Unlock()
		return
	}
	kh.known[h] = struct{}{}
	kh.mu.Unlock()
	_ = kh.persist()
}
