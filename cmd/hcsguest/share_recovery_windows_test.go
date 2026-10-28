//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

func TestPreviousBootRejectsUnownedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "share")
	r := shareIntent{Transport: "smb-tcp", Path: path, Source: `\\server\share`}
	if err := recoverPreviousBootShare(r); err != nil {
		t.Fatalf("missing link: %v", err)
	}
	if err := os.WriteFile(path, []byte("unowned"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := recoverPreviousBootShare(r); err == nil {
		t.Fatal("accepted unowned path")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("unowned path removed: %v", err)
	}
}

func TestPreviousBootForgetsOnlyMatchingOwner(t *testing.T) {
	oldGet, oldForget := previousBootOwner, forgetPreviousBootOwner
	t.Cleanup(func() { previousBootOwner, forgetPreviousBootOwner = oldGet, oldForget })
	r := shareIntent{BootID: "old", Transport: "smb-tcp", Path: filepath.Join(t.TempDir(), "absent"), Source: `\\server\share`, MappingKey: "key", MappingToken: "token", Port: 445}
	owner := globalRequest{Key: "key", Token: "token", Remote: r.Source, User: "guest", Port: 445}
	previousBootOwner = func(string) (wnetRecord, bool, error) { return wnetRecord{Boot: "old", Owner: owner}, true, nil }
	calls := 0
	forgetPreviousBootOwner = func(got globalRequest) error {
		calls++
		if got != owner {
			t.Fatal("owner changed")
		}
		return nil
	}
	if err := recoverPreviousBootShare(r); err != nil || calls != 1 {
		t.Fatalf("recovery: %v calls=%d", err, calls)
	}
	owner.Token = "replacement"
	if err := recoverPreviousBootShare(r); err == nil || calls != 1 {
		t.Fatal("forgot unowned record")
	}
}

func TestRecoveredGlobalMappingReferences(t *testing.T) {
	owner := globalRequest{Key: "key", Token: "token", Remote: `\\server\share`, User: "guest", Port: 445}
	for _, tc := range []struct {
		name                       string
		pending, badLink, badOwner bool
	}{
		{name: "complete"}, {name: "pending member", pending: true}, {name: "replaced link", badLink: true}, {name: "owner mismatch", badOwner: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			removes, unlinks := 0, 0
			m := globalManager{ops: globalOps{
				linkIdentity: func(path, _ string) (uint32, uint64, error) {
					if tc.badLink && path == `C:\b` {
						return 1, 99, nil
					}
					return 1, 2, nil
				},
				removeIdentity: func(_ string, _ string, volume uint32, index uint64) error {
					if volume != 1 || index != 2 {
						return errors.New("identity")
					}
					unlinks++
					return nil
				},
				verify: func(globalRequest) error {
					if tc.badOwner {
						return errors.New("owner changed")
					}
					return nil
				},
				command: func(globalRequest) error { removes++; return nil },
			}}
			newEntry := func(path string) *shareEntry {
				return &shareEntry{intent: shareIntent{State: "mounted", Source: owner.Remote, Path: path, Transport: "smb-tcp", Port: 445, MappingKey: owner.Key, MappingToken: owner.Token, LinkVolume: 1, LinkIndex: 2}}
			}
			a, b := newEntry(`C:\a`), newEntry(`C:\b`)
			if tc.pending {
				b.intent.State = "pending"
			}
			m.recoverBatch(map[string]*shareEntry{"a": a, "b": b}, func() ([]globalRequest, error) { return []globalRequest{owner}, nil })
			if tc.pending || tc.badLink || tc.badOwner {
				if a.cleanup != nil || b.cleanup != nil || !m.entries[`\\server\share`].blocked {
					t.Fatal("unverified group was recovered")
				}
				return
			}
			if a.cleanup == nil || b.cleanup == nil {
				t.Fatal("missing cleanup")
			}
			if err := a.cleanup(); err != nil || removes != 0 || unlinks != 1 {
				t.Fatalf("first cleanup: %v removals %d links %d", err, removes, unlinks)
			}
			if err := b.cleanup(); err != nil || removes != 1 || unlinks != 2 {
				t.Fatalf("second cleanup: %v removals %d links %d", err, removes, unlinks)
			}
		})
	}
}

func TestSMBJournalRestartSharedCleanup(t *testing.T) {
	const boot = "12345678-1234-4123-8123-123456789abc"
	var owner globalRequest
	removals := 0
	ops := globalOps{
		command: func(r globalRequest) error {
			if r.Op == "add" {
				owner = r
				owner.Op = "remove"
				owner.Password = ""
			} else {
				removals++
			}
			return nil
		},
		link:           func(string, string) error { return nil },
		linkIdentity:   func(string, string) (uint32, uint64, error) { return 10, 20, nil },
		stage:          func(r *shareIntent, persist func() error) error { r.LinkVolume, r.LinkIndex = 10, 20; return persist() },
		removeIdentity: func(string, string, uint32, uint64) error { return nil },
		verify: func(r globalRequest) error {
			if r.Token != owner.Token || r.Key != owner.Key {
				return errors.New("owner mismatch")
			}
			return nil
		},
	}
	j := &memoryShareJournal{}
	first := &globalManager{ops: ops}
	m := shareManager{journal: j, bootID: func() (string, error) { return boot, nil }, mountIntent: first.mountIntent, capture: captureShareIntent}
	for _, id := range []string{"a", "b"} {
		s := &guestproto.Share{ID: id, Generation: 1, BootID: boot, Path: filepath.Join(t.TempDir(), id), Transport: "smb-tcp", Source: `\\server\share`, User: "private-user", Password: "private-password", Port: 445}
		if r := m.mount(s); !r.OK {
			t.Fatalf("mount %s: %+v", id, r)
		}
	}
	conflict := &guestproto.Share{ID: "different", Generation: 1, BootID: boot, Path: filepath.Join(t.TempDir(), "different"), Transport: "smb-tcp", Source: `\\server\share`, User: "private-user", Password: "wrong", Port: 445}
	if r := m.mount(conflict); r.ErrorCode != "conflict" {
		t.Fatalf("credential conflict: %+v", r)
	}
	for _, r := range j.records {
		if r.ID == "different" && r.State == "absent" {
			continue
		}
		if r.State != "mounted" || r.LinkIndex != 20 || r.MappingToken != owner.Token {
			t.Fatalf("incomplete durable record: %+v", r)
		}
	}
	data, _ := json.Marshal(j.records)
	if strings.Contains(string(data), "private-user") || strings.Contains(string(data), "private-password") {
		t.Fatal("credential in journal")
	}
	recovered := &globalManager{ops: ops}
	m2 := shareManager{journal: j, bootID: m.bootID, recoverBatch: func(entries map[string]*shareEntry) {
		recovered.recoverBatch(entries, func() ([]globalRequest, error) { return []globalRequest{owner}, nil })
	}}
	if err := m2.recoverAtStartup(); err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"a", "b"} {
		r := m2.unmount(&guestproto.ShareRef{ID: id, Generation: 1, BootID: boot})
		if !r.OK || removals != i {
			t.Fatalf("unmount %s: %+v removals=%d", id, r, removals)
		}
	}
}

func TestFailedConnectionCleanup(t *testing.T) {
	const boot = "12345678-1234-4123-8123-123456789abc"
	oldGet, oldForget := previousBootOwner, forgetPreviousBootOwner
	t.Cleanup(func() { previousBootOwner, forgetPreviousBootOwner = oldGet, oldForget })
	var record wnetRecord
	connected := true
	previousBootOwner = func(string) (wnetRecord, bool, error) { return record, true, nil }
	forgetPreviousBootOwner = func(owner globalRequest) error {
		if owner != record.Owner || connected {
			return errors.New("connection uncertain")
		}
		return nil
	}
	ops := globalOps{command: func(owner globalRequest) error {
		owner.Password, owner.Op = "", "remove"
		record = wnetRecord{Owner: owner, Boot: boot, Phase: "intent"}
		return errors.New("add failed")
	}}
	j := &memoryShareJournal{}
	backend := &globalManager{ops: ops}
	m := shareManager{journal: j, bootID: func() (string, error) { return boot, nil }, mountIntent: backend.mountIntent}
	s := &guestproto.Share{ID: "failed", Generation: 1, BootID: boot, Path: filepath.Join(t.TempDir(), "mount"), Transport: "smb-tcp", Source: `\\server\share`, User: "user", Password: "bad"}
	if r := m.mount(s); r.ErrorCode != "mount_failed" {
		t.Fatalf("mount: %+v", r)
	}
	ref := &guestproto.ShareRef{ID: s.ID, Generation: s.Generation, BootID: boot}
	if r := m.unmount(ref); r.OK {
		t.Fatal("removed uncertain connected intent")
	}
	connected = false
	if r := m.unmount(ref); !r.OK || r.State != "absent" {
		t.Fatalf("unmount: %+v", r)
	}
}

func TestRecoveredFailedConnectionCleanup(t *testing.T) {
	const boot = "12345678-1234-4123-8123-123456789abc"
	oldGet, oldForget := previousBootOwner, forgetPreviousBootOwner
	t.Cleanup(func() { previousBootOwner, forgetPreviousBootOwner = oldGet, oldForget })
	owner := globalRequest{Key: "key", Token: "token", Remote: `\\server\share`, User: "user"}
	record := wnetRecord{Owner: owner, Boot: boot, Phase: "intent"}
	previousBootOwner = func(string) (wnetRecord, bool, error) { return record, true, nil }
	connected := true
	forgetPreviousBootOwner = func(globalRequest) error {
		if connected {
			return errors.New("uncertain")
		}
		return nil
	}
	r := shareIntent{BootID: boot, ID: "failed", Generation: 1, Path: filepath.Join(t.TempDir(), "mount"), Source: owner.Remote, Transport: "smb-tcp", State: "pending", MappingKey: owner.Key, MappingToken: owner.Token}
	j := &memoryShareJournal{records: []shareIntent{r}}
	backend := &globalManager{}
	m := shareManager{journal: j, bootID: func() (string, error) { return boot, nil }, recoverBatch: func(e map[string]*shareEntry) {
		backend.recoverBatch(e, func() ([]globalRequest, error) { return []globalRequest{owner}, nil })
	}}
	ref := &guestproto.ShareRef{ID: r.ID, Generation: 1, BootID: boot}
	if result := m.unmount(ref); result.OK {
		t.Fatal("removed uncertain connection")
	}
	connected = false
	if result := m.unmount(ref); !result.OK || result.State != "absent" {
		t.Fatalf("cleanup: %+v", result)
	}
}

func TestOwnedLinkIdentityAndReplacement(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	volume, index, err := ownedLinkIdentity(link, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := removeIdentifiedLink(link, target, volume, index+1); err == nil {
		t.Fatal("wrong identity accepted")
	}
	if err := removeIdentifiedLink(link, target, volume, index); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("link remains: %v", err)
	}
}
