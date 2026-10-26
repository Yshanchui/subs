package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Proxy map[string]any

type Source struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Enabled     bool      `json:"enabled"`
	Cache       []Proxy   `json:"cache,omitempty"`
	UpdatedAt   time.Time `json:"updatedAt"`
	AttemptedAt time.Time `json:"attemptedAt"`
	Error       string    `json:"error,omitempty"`
	Warnings    []string  `json:"warnings,omitempty"`
}

type Artifact struct {
	Nodes         int       `json:"nodes"`
	ExcludedNodes int       `json:"excludedNodes"`
	Rules         int       `json:"rules"`
	ExcludedRules int       `json:"excludedRules"`
	SHA256        string    `json:"sha256"`
	UpdatedAt     time.Time `json:"updatedAt"`
	Error         string    `json:"error,omitempty"`
}

type Publication struct {
	Generation    string               `json:"generation"`
	Previous      string               `json:"previous,omitempty"`
	BuiltAt       time.Time            `json:"builtAt"`
	Artifacts     map[string]Artifact  `json:"artifacts"`
	Sources       map[string]time.Time `json:"sources"`
	RuleUpdatedAt time.Time            `json:"ruleUpdatedAt"`
}

type Collection struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	AllSources  bool         `json:"allSources"`
	SourceIDs   []string     `json:"sourceIds"`
	Token       string       `json:"token"`
	Publication *Publication `json:"publication,omitempty"`
	Error       string       `json:"error,omitempty"`
}

type Settings struct {
	SourceIntervalMinutes int `json:"sourceIntervalMinutes"`
	RuleIntervalHours     int `json:"ruleIntervalHours"`
}

type State struct {
	Version         int          `json:"version"`
	Username        string       `json:"username"`
	PasswordHash    string       `json:"passwordHash"`
	Sources         []Source     `json:"sources"`
	Collections     []Collection `json:"collections"`
	ACL             *ACL         `json:"acl,omitempty"`
	RuleAttemptedAt time.Time    `json:"ruleAttemptedAt"`
	RuleError       string       `json:"ruleError,omitempty"`
	Settings        Settings     `json:"settings"`
}

type Store struct {
	mu    sync.RWMutex
	dir   string
	state State
	lock  *os.File
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func openStore(dir, username, hash string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	lock, err := lockDataDir(dir)
	if err != nil {
		return nil, err
	}
	s.lock = lock
	opened := false
	defer func() {
		if !opened {
			_ = lock.Close()
		}
	}()
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err == nil {
		if err = json.Unmarshal(b, &s.state); err != nil {
			return nil, errors.New("state.json 无法解析，已停止以保护原数据")
		}
		if s.state.Version != 1 || s.state.PasswordHash == "" {
			return nil, errors.New("不支持的数据版本或账号数据损坏")
		}
		opened = true
		return s, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if hash == "" {
		return nil, errors.New("首次启动请设置 SUBS_ADMIN_PASSWORD（12–72 字节）")
	}
	s.state = State{Version: 1, Username: username, PasswordHash: hash, Sources: []Source{}, Collections: []Collection{{ID: randomToken(8), Name: "聚合订阅", AllSources: true, SourceIDs: []string{}, Token: randomToken(24)}}, Settings: Settings{360, 24}}
	if err := s.save(s.state); err != nil {
		return nil, err
	}
	opened = true
	return s, nil
}

func (s *Store) Close() error {
	if s.lock != nil {
		return s.lock.Close()
	}
	return nil
}

func cloneState(s State) State {
	b, _ := json.Marshal(s)
	var c State
	if err := json.Unmarshal(b, &c); err != nil {
		panic(err)
	}
	return c
}

func (s *Store) snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state)
}

func (s *Store) mutate(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	if err := fn(&next); err != nil {
		return err
	}
	if err := s.save(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *Store) save(next State) error {
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.dir, "state.json"), b)
}

func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if d, e := os.Open(filepath.Dir(path)); e == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
