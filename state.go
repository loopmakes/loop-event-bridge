package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Observation struct {
	Key         string
	Fingerprint string
	Timestamp   time.Time
	Data        map[string]any
}
type Delivery struct {
	Mode   string `json:"mode"`
	URL    string `json:"url"`
	Secret string `json:"secret,omitempty"`
}
type Arguments struct{}
type Subscription struct {
	ID, Owner, Name string
	Arguments       Arguments
	Delivery        Delivery
	Expires         time.Time
	OldSecret       string
	RotateUntil     time.Time
}
type Event struct {
	ID        string         `json:"eventId"`
	Name      string         `json:"name"`
	Timestamp time.Time      `json:"timestamp"`
	Data      map[string]any `json:"data"`
	Cursor    any            `json:"cursor"`
}
type Pending struct {
	SubscriptionID string
	Event          Event
	Attempts       int
	Next           time.Time
	Dead           bool
}
type State struct {
	Version       int
	Subscriptions map[string]Subscription
	Seen          map[string]string
	Baselines     map[string]bool
	Queue         []Pending
	LastPoll      time.Time
	LastError     string
}
type Store struct {
	mu    sync.Mutex
	path  string
	state State
}

func openStore(path string) (*Store, error) {
	s := &Store{path: path, state: State{Version: 1, Subscriptions: map[string]Subscription{}, Seen: map[string]string{}, Baselines: map[string]bool{}, Queue: []Pending{}}}
	info, statErr := os.Stat(path)
	if statErr == nil && info.Size() > 64<<20 {
		return nil, errors.New("state too large")
	}
	if statErr == nil && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state permissions must be 0600")
	}
	b, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return s, nil
	}
	if e != nil {
		return nil, e
	}
	if len(b) > 64<<20 {
		return nil, errors.New("state too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if e = dec.Decode(&s.state); e != nil {
		return nil, e
	}
	if dec.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid trailing state data")
	}
	if s.state.Version != 1 || s.state.Subscriptions == nil || s.state.Seen == nil || s.state.Baselines == nil {
		return nil, errors.New("invalid state")
	}
	return s, nil
}

// Persist one complete transaction, then publish it in memory. Caller holds mu.
func (s *Store) save(next State) error {
	b, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if len(b) > 64<<20 {
		return errors.New("state capacity reached")
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".state-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(f.Name(), s.path)
	}
	if e != nil {
		return e
	}
	s.state = next // rename committed; keep memory aligned even if directory fsync fails
	d, e := os.Open(filepath.Dir(s.path))
	if e == nil {
		e = d.Sync()
		d.Close()
	}
	if e != nil {
		return e
	}
	s.state = next
	return nil
}
func (s *Store) copy() State {
	b, _ := json.Marshal(s.state)
	var n State
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	_ = dec.Decode(&n)
	return n
}
