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
var errSharePrerequisiteMissing = errors.New("share prerequisite missing")
var errShareTransportUnavailable = errors.New("share transport unavailable")
var errShareBusy = errors.New("managed share is busy")
var errShareJournal = errors.New("share journal unavailable")
var errBootMismatch = errors.New("boot identity mismatch")

type shareEntry struct {
	result      guestproto.ShareResult
	fingerprint [32]byte
	cleanup     func() error
	intent      shareIntent
}

type shareManager struct {
	mu           sync.Mutex
	entries      map[string]*shareEntry
	backend      shareBackend
	mountIntent  func(*guestproto.Share, *shareIntent, func() error) (func() error, error)
	bootTime     func() time.Time
	bootID       func() (string, error)
	identity     string // protected by mu and refreshed before each operation
	journal      shareJournal
	loaded       bool
	capture      func(*shareIntent) error
	recover      func(shareIntent) (func() error, error)
	recoverBatch func(map[string]*shareEntry)
}

var managedShares = &shareManager{backend: mountManagedShare, mountIntent: mountManagedShareIntent, bootID: readBootID, journal: newShareJournal(), capture: captureShareIntent, recoverBatch: recoverShareBatch, bootTime: func() time.Time {
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

func (m *shareManager) prepare(expected string) error {
	m.identity = ""
	id, err := m.bootIdentity()
	if err != nil {
		return err
	}
	m.identity = id
	if expected != id {
		return errBootMismatch
	}
	if m.loaded || m.journal == nil {
		return nil
	}
	records, err := m.journal.load()
	if err != nil {
		return errShareJournal
	}
	m.entries = make(map[string]*shareEntry)
	for _, rec := range records {
		if rec.BootID != id {
			continue
		}
		if !rec.valid() || m.entries[rec.ID] != nil {
			return errShareJournal
		}
		r := m.result(rec.ID, rec.Generation, "recovery_required")
		r.State, r.Path, r.Transport, r.ReadOnly = "recovery_required", rec.Path, rec.Transport, rec.ReadOnly
		if rec.State == "absent" {
			r.OK, r.ErrorCode, r.State = true, "", "absent"
		}
		e := &shareEntry{result: r, fingerprint: rec.Fingerprint, intent: rec}
		m.entries[rec.ID] = e
	}
	// Validate the entire journal before recovery opens any native resources.
	if m.recoverBatch != nil {
		m.recoverBatch(m.entries)
	} else if m.recover != nil {
		for _, e := range m.entries {
			if e.intent.State != "absent" {
				e.cleanup, _ = m.recover(e.intent)
			}
		}
	}
	m.loaded = true
	return nil
}

// recoverAtStartup uses the local boot identity, not a client-supplied value.
func (m *shareManager) recoverAtStartup() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, err := m.bootIdentity()
	if err != nil {
		return err
	}
	return m.prepare(id)
}

func (m *shareManager) prepareFailure(id string, generation uint64, err error) guestproto.ShareResult {
	if errors.Is(err, errBootMismatch) {
		return m.result(id, generation, "boot_mismatch")
	}
	if errors.Is(err, errShareJournal) {
		return m.result(id, generation, "recovery_required")
	}
	return m.result(id, generation, "boot_id_unavailable")
}

func (m *shareManager) persist() error {
	if m.journal == nil {
		return nil
	}
	records := make([]shareIntent, 0, len(m.entries))
	for _, e := range m.entries {
		records = append(records, e.intent)
	}
	return m.journal.save(records)
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
	var id, bootID string
	var generation uint64
	if s != nil {
		id, generation, bootID = s.ID, s.Generation, s.BootID
	}
	if err := m.prepare(bootID); err != nil {
		return m.prepareFailure(id, generation, err)
	}
	if s == nil {
		return m.result("", 0, "invalid_request")
	}
	if !validShareID(s.ID) || s.Generation == 0 || s.Transport == "" || s.Source == "" || !filepath.IsAbs(s.Path) || s.Path != filepath.Clean(s.Path) || s.UID < 0 || s.GID < 0 {
		return m.result(s.ID, s.Generation, "invalid_request")
	}
	b, _ := json.Marshal(s)
	fingerprint := sha256.Sum256(b)
	clear(b)
	if m.entries == nil {
		m.entries = make(map[string]*shareEntry)
	}
	if old := m.entries[s.ID]; old != nil {
		if old.result.State == "recovery_required" {
			return old.result
		}
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
		if (e.result.State == "mounted" || e.result.State == "recovery_required") && pathsOverlap(sharePath(e.result.Path), sharePath(s.Path)) {
			return m.result(s.ID, s.Generation, "path_in_use")
		}
	}
	intent := newShareIntent(s, m.identity, fingerprint)
	pending := m.result(s.ID, s.Generation, "recovery_required")
	pending.State, pending.Path, pending.Transport, pending.ReadOnly = "recovery_required", s.Path, s.Transport, s.ReadOnly
	e := &shareEntry{result: pending, fingerprint: fingerprint, intent: intent}
	m.entries[s.ID] = e
	if err := m.persist(); err != nil {
		return pending
	}
	var cleanup func() error
	var err error
	if m.mountIntent != nil {
		cleanup, err = m.mountIntent(s, &e.intent, m.persist)
	} else {
		cleanup, err = m.backend(s)
	}
	if errors.Is(err, errShareJournal) {
		return pending
	}
	if cleanup != nil {
		e.cleanup = cleanup
	}
	code := ""
	switch {
	case errors.Is(err, errShareNotImplemented):
		code = "not_implemented"
	case errors.Is(err, errSharePrerequisiteMissing):
		code = "missing_prerequisite"
	case errors.Is(err, errShareTransportUnavailable):
		code = "transport_unavailable"
	}
	if code != "" && cleanup == nil {
		e.intent.State = "absent"
		if err := m.persist(); err != nil {
			e.intent.State = "pending"
			return pending
		}
		e.result = m.result(s.ID, s.Generation, "")
		return m.result(s.ID, s.Generation, code)
	}
	if err != nil || cleanup == nil {
		return m.result(s.ID, s.Generation, "mount_failed")
	}
	r := m.result(s.ID, s.Generation, "")
	r.State, r.Transport, r.Path, r.ReadOnly = "mounted", s.Transport, s.Path, s.ReadOnly
	if m.capture != nil {
		if err := m.capture(&e.intent); err != nil {
			return pending
		}
	}
	e.intent.State = "mounted"
	if err := m.persist(); err != nil {
		return pending
	}
	e.result = r
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
	var id, bootID string
	var generation uint64
	if ref != nil {
		id, generation, bootID = ref.ID, ref.Generation, ref.BootID
	}
	if err := m.prepare(bootID); err != nil {
		return m.prepareFailure(id, generation, err)
	}
	_, r := m.lookup(ref)
	return r
}

func (m *shareManager) unmount(ref *guestproto.ShareRef) guestproto.ShareResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	var id, bootID string
	var generation uint64
	if ref != nil {
		id, generation, bootID = ref.ID, ref.Generation, ref.BootID
	}
	if err := m.prepare(bootID); err != nil {
		return m.prepareFailure(id, generation, err)
	}
	e, r := m.lookup(ref)
	if e == nil || e.result.State == "absent" {
		return r
	}
	if e.cleanup == nil {
		// Cleanup completed in this process, but its final journal write failed.
		if e.intent.State == "absent" && m.persist() == nil {
			e.result.OK, e.result.ErrorCode, e.result.State = true, "", "absent"
			return e.result
		}
		return r
	}
	// Once teardown starts, a later reused kernel mount ID must not authorize
	// cleanup after a crash between unmount and the final journal update.
	e.intent.State = "pending"
	if err := m.persist(); err != nil {
		r.OK, r.ErrorCode, r.State = false, "recovery_required", "recovery_required"
		return r
	}
	if err := e.cleanup(); err != nil {
		r.OK = false
		r.ErrorCode = "unmount_failed"
		if e.result.State == "recovery_required" {
			r.ErrorCode = "recovery_required"
		}
		if errors.Is(err, errShareBusy) {
			r.ErrorCode = "busy"
		}
		return r
	}
	e.cleanup = nil
	e.result.State = "absent"
	e.result.OK, e.result.ErrorCode = true, ""
	e.intent.State = "absent"
	if err := m.persist(); err != nil {
		e.result.OK = false
		e.result.State = "recovery_required"
		e.result.ErrorCode = "recovery_required"
	}
	return e.result
}
