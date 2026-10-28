package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// The backend owns native resources until its cleanup succeeds. Errors are not
// sent over the wire because platform errors can contain credentials.
type shareBackend func(*guestproto.Share) (func() error, error)

var errShareNotImplemented = errors.New("managed shares not implemented")
var errShareBusy = errors.New("managed share is busy")

type shareEntry struct {
	result      guestproto.ShareResult
	fingerprint [32]byte
	cleanup     func() error
}

type shareManager struct {
	mu       sync.Mutex
	entries  map[string]*shareEntry
	backend  shareBackend
	bootTime func() time.Time
	bootID   func() (string, error)
	identity string // protected by mu and refreshed before each operation
}

var managedShares = &shareManager{backend: mountManagedShare, bootID: readBootID, bootTime: func() time.Time {
	info, err := gatherInfo()
	if err != nil {
		return time.Time{}
	}
	return info.BootTimeUTC
}}

func (m *shareManager) result(id string, generation uint64, code string) guestproto.ShareResult {
	var boot time.Time
	if m.bootTime != nil {
		boot = m.bootTime()
	}
	return guestproto.ShareResult{OK: code == "", Protocol: guestproto.Protocol, ID: id, Generation: generation, State: "absent", BootID: m.identity, BootTimeUTC: boot, ErrorCode: code}
}

func (m *shareManager) bootIdentity() (string, error) {
	if m.bootID == nil {
		return "", errors.New("boot identity unavailable")
	}
	id, err := m.bootID()
	if err != nil || !validBootID(id) {
		return "", errors.New("boot identity unavailable")
	}
	return id, nil
}

func validShareID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func sharePath(path string) string {
	p := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

func (m *shareManager) mount(s *guestproto.Share) guestproto.ShareResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	var err error
	if m.identity, err = m.bootIdentity(); err != nil {
		return m.result("", 0, "boot_id_unavailable")
	}
	if s == nil {
		return m.result("", 0, "invalid_request")
	}
	if !validShareID(s.ID) || s.Generation == 0 || s.Transport == "" || s.Source == "" || !filepath.IsAbs(s.Path) || s.Path != filepath.Clean(s.Path) || s.UID < 0 || s.GID < 0 {
		return m.result(s.ID, s.Generation, "invalid_request")
	}
	b, _ := json.Marshal(s)
	fingerprint := sha256.Sum256(b)
	if m.entries == nil {
		m.entries = make(map[string]*shareEntry)
	}
	if old := m.entries[s.ID]; old != nil {
		if s.Generation < old.result.Generation || (s.Generation == old.result.Generation && old.result.State == "absent") {
			return m.result(s.ID, s.Generation, "stale_generation")
		}
		if old.result.State == "mounted" {
			if s.Generation == old.result.Generation && old.fingerprint == fingerprint {
				return old.result
			}
			return m.result(s.ID, s.Generation, "conflict")
		}
	}
	for _, e := range m.entries {
		if e.result.State == "mounted" && pathsOverlap(sharePath(e.result.Path), sharePath(s.Path)) {
			return m.result(s.ID, s.Generation, "path_in_use")
		}
	}
	cleanup, err := m.backend(s)
	if errors.Is(err, errShareNotImplemented) {
		return m.result(s.ID, s.Generation, "not_implemented")
	}
	if err != nil || cleanup == nil {
		return m.result(s.ID, s.Generation, "mount_failed")
	}
	r := m.result(s.ID, s.Generation, "")
	r.State, r.Transport, r.Path, r.ReadOnly = "mounted", s.Transport, s.Path, s.ReadOnly
	m.entries[s.ID] = &shareEntry{result: r, fingerprint: fingerprint, cleanup: cleanup}
	return r
}

func pathsOverlap(a, b string) bool {
	within := func(parent, child string) bool {
		r, err := filepath.Rel(parent, child)
		return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
	}
	return within(a, b) || within(b, a)
}

func (m *shareManager) lookup(ref *guestproto.ShareRef) (*shareEntry, guestproto.ShareResult) {
	if ref == nil {
		return nil, m.result("", 0, "invalid_request")
	}
	if !validShareID(ref.ID) || ref.Generation == 0 {
		return nil, m.result(ref.ID, ref.Generation, "invalid_request")
	}
	e := m.entries[ref.ID]
	if e == nil {
		return nil, m.result(ref.ID, ref.Generation, "not_found")
	}
	if e.result.Generation != ref.Generation {
		return nil, m.result(ref.ID, ref.Generation, "stale_generation")
	}
	return e, e.result
}

func (m *shareManager) status(ref *guestproto.ShareRef) guestproto.ShareResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	var err error
	if m.identity, err = m.bootIdentity(); err != nil {
		return m.result("", 0, "boot_id_unavailable")
	}
	_, r := m.lookup(ref)
	return r
}

func (m *shareManager) unmount(ref *guestproto.ShareRef) guestproto.ShareResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	var err error
	if m.identity, err = m.bootIdentity(); err != nil {
		return m.result("", 0, "boot_id_unavailable")
	}
	e, r := m.lookup(ref)
	if e == nil || e.result.State == "absent" {
		return r
	}
	if err := e.cleanup(); err != nil {
		r.OK = false
		r.ErrorCode = "unmount_failed"
		if errors.Is(err, errShareBusy) {
			r.ErrorCode = "busy"
		}
		return r
	}
	e.cleanup = nil
	e.result.State = "absent"
	return e.result
}
