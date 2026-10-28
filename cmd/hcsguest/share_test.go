package main

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

func TestManagedShareLifecycle(t *testing.T) {
	var mounts, unmounts int
	busy := true
	m := shareManager{bootID: func() (string, error) { return "12345678-1234-4123-8123-123456789abc", nil }, bootTime: func() time.Time { return time.Unix(123, 0).UTC() }, backend: func(*guestproto.Share) (func() error, error) {
		mounts++
		return func() error {
			unmounts++
			if busy {
				return errors.New("busy")
			}
			return nil
		}, nil
	}}
	s := &guestproto.Share{ID: "one", Generation: 1, BootID: "12345678-1234-4123-8123-123456789abc", Transport: "cifs", Source: "source", Path: filepath.Join(t.TempDir(), "mount"), User: "user", Password: "secret"}
	ref := &guestproto.ShareRef{ID: s.ID, Generation: 1, BootID: s.BootID}
	if r := m.mount(s); !r.OK || r.State != "mounted" || r.BootTimeUTC.Unix() != 123 || r.BootID != "12345678-1234-4123-8123-123456789abc" {
		t.Fatalf("mount: %+v", r)
	}
	if r := m.mount(s); !r.OK || mounts != 1 {
		t.Fatalf("idempotence: %+v mounts=%d", r, mounts)
	}
	changed := *s
	changed.Password = "different"
	if r := m.mount(&changed); r.ErrorCode != "conflict" {
		t.Fatalf("conflict: %+v", r)
	}
	other := *s
	other.ID = "two"
	other.Path = filepath.Join(s.Path, "nested")
	if r := m.mount(&other); r.ErrorCode != "path_in_use" {
		t.Fatalf("path collision: %+v", r)
	}
	if r := m.status(&guestproto.ShareRef{ID: "unknown", Generation: 1, BootID: s.BootID}); r.ErrorCode != "not_found" {
		t.Fatalf("missing: %+v", r)
	}
	if r := m.unmount(&guestproto.ShareRef{ID: s.ID, Generation: 2, BootID: s.BootID}); r.ErrorCode != "stale_generation" || unmounts != 0 {
		t.Fatalf("stale: %+v", r)
	}
	if r := m.unmount(ref); r.ErrorCode != "unmount_failed" || r.State != "mounted" {
		t.Fatalf("busy: %+v", r)
	}
	busy = false
	if r := m.unmount(ref); !r.OK || r.State != "absent" {
		t.Fatalf("unmount: %+v", r)
	}
	if r := m.unmount(ref); !r.OK || unmounts != 2 {
		t.Fatalf("repeat: %+v", r)
	}
	if r := m.mount(s); r.ErrorCode != "stale_generation" {
		t.Fatalf("old generation: %+v", r)
	}
	s.Generation++
	if r := m.mount(s); !r.OK || mounts != 2 {
		t.Fatalf("new generation: %+v", r)
	}
}

func TestShareBootPrecondition(t *testing.T) {
	const current = "12345678-1234-4123-8123-123456789abc"
	const old = "abcdefab-1234-4123-8123-123456789abc"
	mounts, unmounts := 0, 0
	m := shareManager{bootID: func() (string, error) { return current, nil }, backend: func(*guestproto.Share) (func() error, error) {
		mounts++
		return func() error { unmounts++; return nil }, nil
	}}
	s := &guestproto.Share{ID: "same", Generation: 7, BootID: current, Transport: "test", Source: "source", Path: filepath.Join(t.TempDir(), "mount")}
	if r := m.mount(s); !r.OK {
		t.Fatalf("mount: %+v", r)
	}
	for _, boot := range []string{"", old} {
		ref := &guestproto.ShareRef{ID: s.ID, Generation: s.Generation, BootID: boot}
		for _, r := range []guestproto.ShareResult{m.status(ref), m.unmount(ref)} {
			if r.OK || r.ErrorCode != "boot_mismatch" || r.ID != s.ID || r.Generation != s.Generation || r.BootID != current {
				t.Fatalf("mismatch: %+v", r)
			}
		}
		wrong := *s
		wrong.BootID = boot
		if r := m.mount(&wrong); r.OK || r.ErrorCode != "boot_mismatch" || r.ID != s.ID || r.Generation != s.Generation || r.BootID != current {
			t.Fatalf("wrong boot mount: %+v", r)
		}
	}
	if mounts != 1 || unmounts != 0 {
		t.Fatalf("side effects: mounts=%d unmounts=%d", mounts, unmounts)
	}
	if r := m.unmount(&guestproto.ShareRef{ID: s.ID, Generation: s.Generation, BootID: current}); !r.OK || unmounts != 1 {
		t.Fatalf("current boot unmount: %+v", r)
	}
	blocked := shareManager{bootID: m.bootID, journal: &memoryShareJournal{fail: true}}
	if r := blocked.status(&guestproto.ShareRef{ID: "s", Generation: 3, BootID: old}); r.ErrorCode != "boot_mismatch" || r.BootID != current {
		t.Fatalf("boot check must precede journal access: %+v", r)
	}
}

func TestSharePreparationFailurePreservesRequest(t *testing.T) {
	const boot = "12345678-1234-4123-8123-123456789abc"
	for _, tc := range []struct {
		name           string
		bootID         func() (string, error)
		journal        shareJournal
		code, identity string
	}{
		{"boot unavailable", func() (string, error) { return "", errors.New("offline") }, nil, "boot_id_unavailable", ""},
		{"journal unavailable", func() (string, error) { return boot, nil }, &memoryShareJournal{fail: true}, "recovery_required", boot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := shareManager{bootID: tc.bootID, journal: tc.journal}
			s := &guestproto.Share{ID: "s", Generation: 8, BootID: boot}
			ref := &guestproto.ShareRef{ID: s.ID, Generation: s.Generation, BootID: boot}
			for _, r := range []guestproto.ShareResult{m.mount(s), m.status(ref), m.unmount(ref)} {
				if r.ErrorCode != tc.code || r.ID != s.ID || r.Generation != s.Generation || r.BootID != tc.identity {
					t.Fatalf("failure: %+v", r)
				}
			}
		})
	}
}

func TestUnsupportedShareTombstone(t *testing.T) {
	const boot = "12345678-1234-4123-8123-123456789abc"
	j := &memoryShareJournal{}
	m := shareManager{journal: j, bootID: func() (string, error) { return boot, nil }, backend: func(*guestproto.Share) (func() error, error) { return nil, errShareNotImplemented }}
	s := &guestproto.Share{ID: "s", Generation: 1, BootID: boot, Transport: "unknown", Source: "source", Path: filepath.Join(t.TempDir(), "mount")}
	if r := m.mount(s); r.ErrorCode != "not_implemented" {
		t.Fatalf("mount: %+v", r)
	}
	if len(j.records) != 1 || j.records[0].State != "absent" {
		t.Fatalf("journal: %+v", j.records)
	}
	restarted := shareManager{journal: j, bootID: m.bootID}
	if r := restarted.status(&guestproto.ShareRef{ID: s.ID, Generation: s.Generation, BootID: boot}); !r.OK || r.State != "absent" {
		t.Fatalf("restart: %+v", r)
	}
	if r := restarted.mount(s); r.ErrorCode != "stale_generation" {
		t.Fatalf("tombstone: %+v", r)
	}
}
