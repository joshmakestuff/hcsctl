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
	m := shareManager{bootTime: func() time.Time { return time.Unix(123, 0).UTC() }, backend: func(*guestproto.Share) (func() error, error) {
		mounts++
		return func() error {
			unmounts++
			if busy {
				return errors.New("busy")
			}
			return nil
		}, nil
	}}
	s := &guestproto.Share{ID: "one", Generation: 1, Transport: "cifs", Source: "source", Path: filepath.Join(t.TempDir(), "mount"), User: "user", Password: "secret"}
	ref := &guestproto.ShareRef{ID: s.ID, Generation: 1}
	if r := m.mount(s); !r.OK || r.State != "mounted" || r.BootTimeUTC.Unix() != 123 {
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
	if r := m.status(&guestproto.ShareRef{ID: "unknown", Generation: 1}); r.ErrorCode != "not_found" {
		t.Fatalf("missing: %+v", r)
	}
	if r := m.unmount(&guestproto.ShareRef{ID: s.ID, Generation: 2}); r.ErrorCode != "stale_generation" || unmounts != 0 {
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
