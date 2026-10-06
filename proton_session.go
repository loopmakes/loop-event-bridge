package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

const protonSessionAAD = "loop-event-bridge/proton/session/v1"
const protonSessionMaxBytes = 64 << 10

type protonSavedSession struct {
	AccountID    string `json:"account_id"`
	UID          string `json:"uid"`
	RefreshToken string `json:"refresh_token"`
	LoginHash    string `json:"login_hash,omitempty"`
}
type protonSessionEnvelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type protonSessionStore struct {
	mu     sync.Mutex
	path   string
	aead   cipher.AEAD
	lock   *os.File
	failed bool
	closed bool
}

// Both the key and existing session must be regular private files. O_NOFOLLOW
// rejects final-component symlinks, and O_NONBLOCK prevents FIFO/device opens
// from blocking startup before the regular-file check. The directory must be controlled
// by the operator. The key is never written beside the encrypted session.
func protonReadPrivate(path string, max int) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("Proton private file unavailable")
	}
	f := os.NewFile(uintptr(fd), "proton-private")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Proton private file must be regular with permissions 0600 or stricter")
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(raw) > max {
		return nil, errors.New("Proton private file unreadable or oversized")
	}
	return raw, nil
}

func openProtonSessionStore(path, keyPath string) (*protonSessionStore, error) {
	key, err := protonReadPrivate(keyPath, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if len(key) != 32 {
		return nil, errors.New("Proton session key must contain exactly 32 raw bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("Proton session encryption unavailable")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("Proton session encryption unavailable")
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, errors.New("Proton session directory unavailable")
	}
	// A lifetime advisory lock prevents the service and operator CLI (or another
	// replica) from racing refresh-token rotation. A crash releases the OS lock.
	fd, err := unix.Open(path+".lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errors.New("Proton session lock unavailable")
	}
	lock := os.NewFile(uintptr(fd), "proton-session-lock")
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		lock.Close()
		return nil, errors.New("Proton session lock must be a private regular file")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("Proton session is already in use; stop its poller before authentication")
	}
	return &protonSessionStore{path: path, aead: aead, lock: lock}, nil
}
func (s *protonSessionStore) check() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.failed {
		return errors.New("Proton session persistence unavailable; polling stopped")
	}
	return nil
}
func (s *protonSessionStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.lock != nil {
		_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
		_ = s.lock.Close()
	}
}
func validProtonSession(session protonSavedSession) bool {
	return validProtonID(session.AccountID) && validProtonID(session.UID) && session.RefreshToken != "" && len(session.RefreshToken) <= 8192
}
func (s *protonSessionStore) load() (protonSavedSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.closed {
		return protonSavedSession{}, errors.New("Proton session persistence unavailable")
	}
	raw, err := protonReadPrivate(s.path, protonSessionMaxBytes)
	if err != nil {
		return protonSavedSession{}, errors.New("Proton encrypted session unavailable; run proton-auth")
	}
	var envelope protonSessionEnvelope
	if decodeOAuthJSON(raw, &envelope) != nil || envelope.Version != 1 || len(envelope.Nonce) != s.aead.NonceSize() {
		return protonSavedSession{}, errors.New("Proton encrypted session invalid")
	}
	plaintext, err := s.aead.Open(nil, envelope.Nonce, envelope.Ciphertext, []byte(protonSessionAAD))
	if err != nil {
		return protonSavedSession{}, errors.New("Proton session decryption failed")
	}
	defer clear(plaintext)
	var session protonSavedSession
	if decodeOAuthJSON(plaintext, &session) != nil || !validProtonSession(session) {
		return protonSavedSession{}, errors.New("Proton session data invalid")
	}
	return session, nil
}
func (s *protonSessionStore) save(session protonSavedSession) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.closed {
		return errors.New("Proton session persistence unavailable")
	}
	// Once a rotated credential cannot be durably persisted, never continue using
	// its in-memory value. Error details deliberately exclude paths and tokens.
	defer func() {
		if err != nil {
			s.failed = true
		}
	}()
	if !validProtonSession(session) {
		return errors.New("Proton refresh session invalid")
	}
	plaintext, err := json.Marshal(session)
	if err != nil {
		return errors.New("Proton session encoding failed")
	}
	defer clear(plaintext)
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return errors.New("Proton session nonce unavailable")
	}
	envelope := protonSessionEnvelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plaintext, []byte(protonSessionAAD))}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return errors.New("Proton session encoding failed")
	}
	if len(raw) > protonSessionMaxBytes {
		return errors.New("Proton session exceeds size limit")
	}
	if err = protonAtomicPrivateWrite(s.path, raw); err != nil {
		return errors.New("Proton encrypted session could not be saved; polling stopped")
	}
	return nil
}
func protonAtomicPrivateWrite(path string, raw []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("invalid session target")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".proton-session-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
