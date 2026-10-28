//go:build windows

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

type globalRequest struct {
	Op       string `json:"op"`
	Key      string `json:"key"`
	Token    string `json:"token"`
	Remote   string `json:"remote"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	Port     uint32 `json:"port"`
}
type globalOps struct {
	command        func(globalRequest) error
	link           func(string, string) error
	removeLink     func(string, string) error
	linkIdentity   func(string, string) (uint32, uint64, error)
	removeIdentity func(string, string, uint32, uint64) error
	verify         func(globalRequest) error
	stage          func(*shareIntent, func() error) error
}
type globalEntry struct {
	refs        int
	fingerprint [32]byte
	pending     bool
	owner       globalRequest
	blocked     bool
}
type globalManager struct {
	mu      sync.Mutex
	entries map[string]*globalEntry
	ops     globalOps
}

var globalSMB = globalManager{ops: globalOps{command: runGlobalSMB, link: os.Symlink, removeLink: removeOwnedLink, linkIdentity: ownedLinkIdentity, removeIdentity: removeIdentifiedLink, verify: verifyGlobalSMB, stage: publishStagedLink}}

func verifyGlobalSMB(owner globalRequest) error {
	owner.Op = "check"
	return runGlobalSMB(owner)
}

func removeOwnedLink(path, target string) error {
	got, err := os.Readlink(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, target) {
		return errors.New("mapping link changed")
	}
	return os.Remove(path)
}
func mountGlobalSMB(s *guestproto.Share) (func() error, error) { return globalSMB.mount(s) }
func (m *globalManager) mount(s *guestproto.Share) (func() error, error) {
	return m.mountIntent(s, nil, nil)
}
func (m *globalManager) mountIntent(s *guestproto.Share, intent *shareIntent, persist func() error) (func() error, error) {
	// Do not retain the request or its credentials in cleanup closures.
	source, path := s.Source, s.Path
	parts := strings.Split(strings.TrimPrefix(s.Source, `\\`), `\`)
	if !strings.HasPrefix(s.Source, `\\`) || len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(s.Source, "/\x00") || s.User == "" || (s.Port != 0 && s.Port != 445) {
		return nil, errors.New("invalid SMB mapping")
	}
	key := strings.ToLower(s.Source)
	// Fingerprints avoid keeping credentials in the ownership registry.
	encoded, _ := json.Marshal([]any{s.User, s.Password, s.Port})
	fingerprint := sha256.Sum256(encoded)
	clear(encoded)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = make(map[string]*globalEntry)
	}
	e := m.entries[key]
	if e != nil && e.blocked {
		return nil, errors.New("global mapping recovery required")
	}
	if e != nil && e.pending {
		if err := m.ops.command(e.owner); err != nil {
			return nil, errors.New("pending global mapping cleanup failed")
		}
		delete(m.entries, key)
		e = nil
	}
	if e != nil && e.fingerprint != fingerprint {
		return nil, errShareConflict
	}
	if e != nil && m.ops.verify != nil {
		if err := m.ops.verify(e.owner); err != nil {
			e.blocked = true
			return nil, errors.New("connection ownership uncertain")
		}
	}
	created := e == nil
	if created {
		var token [16]byte
		if _, err := rand.Read(token[:]); err != nil {
			return nil, errors.New("global mapping ownership unavailable")
		}
		digest := sha256.Sum256([]byte(key))
		owner := globalRequest{Op: "remove", Key: hex.EncodeToString(digest[:]), Token: hex.EncodeToString(token[:]), Remote: source, User: s.User, Port: s.Port}
		e = &globalEntry{fingerprint: fingerprint, owner: owner, pending: true}
		m.entries[key] = e
	}
	if intent != nil {
		intent.MappingKey, intent.MappingToken, intent.MappingFingerprint = e.owner.Key, e.owner.Token, fingerprint
		if err := persist(); err != nil {
			if created {
				delete(m.entries, key)
			}
			return nil, errShareJournal
		}
	}
	if created {
		add := e.owner
		add.Op = "add"
		add.Password = s.Password
		if err := m.ops.command(add); err != nil {
			if intent != nil {
				e.blocked = true
				return func() error {
					m.mu.Lock()
					defer m.mu.Unlock()
					if err := cleanupFailedConnection(*intent); err != nil {
						return err
					}
					delete(m.entries, key)
					return nil
				}, fmt.Errorf("connection creation failed; cleanup pending: %w", err)
			}
			return nil, errors.New("global mapping creation failed; cleanup pending")
		}
		e.pending = false
	}
	var linkErr error
	if intent != nil {
		if m.ops.stage == nil {
			linkErr = errors.New("staged link unavailable")
		} else {
			linkErr = m.ops.stage(intent, persist)
		}
	} else {
		linkErr = m.ops.link(s.Source, s.Path)
	}
	if linkErr != nil {
		if intent != nil {
			e.blocked = true
			return nil, errors.Join(errors.New("global mapping link creation uncertain"), linkErr)
		}
		if e.refs == 0 {
			if m.ops.command(e.owner) != nil {
				e.pending = true
			} else {
				delete(m.entries, key)
			}
		}
		return nil, errors.New("global mapping link creation failed")
	}
	e.refs++
	cleanup := m.cleanup(key, e, path, source, intent)
	return cleanup, nil
}

func (m *globalManager) cleanup(key string, e *globalEntry, path, source string, intent *shareIntent) func() error {
	linked := true
	released := false
	return func() error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if e.blocked {
			return errors.New("global mapping recovery required")
		}
		if linked {
			if intent != nil {
				if m.ops.verify(e.owner) != nil {
					return errors.New("global mapping ownership changed")
				}
				var err error
				if intent.LinkPhase != "" {
					err = removeJournalLinks(*intent)
				} else if intent.LinkIndex == 0 {
					err = errors.New("link identity unavailable")
				} else {
					err = m.ops.removeIdentity(path, source, intent.LinkVolume, intent.LinkIndex)
				}
				if err != nil {
					return errors.New("global mapping link removal failed")
				}
			} else if err := m.ops.removeLink(path, source); err != nil {
				return errors.New("global mapping link removal failed")
			}
			linked = false
		}
		if released {
			return nil
		}
		if e.refs == 1 {
			if err := m.ops.command(e.owner); err != nil {
				return errShareBusy
			}
			delete(m.entries, key)
		}
		e.refs--
		released = true
		return nil
	}
}

// recoverGlobalSMBOwnership is the coordinator seam for an ownership record
// recovered from the durable registry; it never removes by UNC alone.
func recoverGlobalSMBOwnership(owner globalRequest) error {
	if owner.Key == "" || owner.Token == "" || owner.Remote == "" || owner.User == "" {
		return errors.New("incomplete global mapping ownership")
	}
	owner.Op = "remove"
	owner.Password = ""
	return runGlobalSMB(owner)
}
