package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

type memoryShareJournal struct {
	records []shareIntent
	fail    bool
}

func (j *memoryShareJournal) load() ([]shareIntent, error) {
	if j.fail {
		return nil, errors.New("failed")
	}
	return append([]shareIntent(nil), j.records...), nil
}
func (j *memoryShareJournal) save(r []shareIntent) error {
	if j.fail {
		return errors.New("failed")
	}
	j.records = append([]shareIntent(nil), r...)
	return nil
}

func TestShareIntentRestart(t *testing.T) {
	const boot = "12345678-1234-4123-8123-123456789abc"
	j := &memoryShareJournal{}
	called := false
	m := shareManager{journal: j, bootID: func() (string, error) { return boot, nil }, backend: func(s *guestproto.Share) (func() error, error) {
		called = true
		if len(j.records) != 1 || j.records[0].State != "pending" {
			t.Fatal("intent not saved before mount")
		}
		return func() error { return nil }, nil
	}}
	s := &guestproto.Share{ID: "share", Generation: 1, Path: filepath.Join(t.TempDir(), "mount"), Transport: "smb-tcp", Source: "source", User: "secret-user", Password: "secret-password"}
	if r := m.mount(s); !r.OK || !called {
		t.Fatalf("mount: %+v", r)
	}
	b, err := json.Marshal(j.records)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), s.User) || strings.Contains(string(b), s.Password) {
		t.Fatalf("credentials in journal: %s", b)
	}
	restarted := shareManager{journal: j, bootID: m.bootID}
	ref := &guestproto.ShareRef{ID: s.ID, Generation: s.Generation}
	if r := restarted.status(ref); r.OK || r.ErrorCode != "recovery_required" || r.State != "recovery_required" {
		t.Fatalf("restart: %+v", r)
	}
	if r := restarted.unmount(ref); r.OK || r.ErrorCode != "recovery_required" {
		t.Fatalf("unverified cleanup: %+v", r)
	}
	j.records[0].State = "pending"
	restarted = shareManager{journal: j, bootID: m.bootID}
	if r := restarted.status(ref); r.OK || r.ErrorCode != "recovery_required" {
		t.Fatalf("pending: %+v", r)
	}
	restarted = shareManager{journal: j, bootID: func() (string, error) { return "abcdefab-1234-4123-8123-123456789abc", nil }}
	if r := restarted.status(ref); r.ErrorCode != "not_found" {
		t.Fatalf("wrong boot: %+v", r)
	}
}

func TestShareIntentWriteFailureBlocksMount(t *testing.T) {
	j := &memoryShareJournal{}
	called := false
	m := shareManager{journal: j, bootID: func() (string, error) { return "12345678-1234-4123-8123-123456789abc", nil }, backend: func(*guestproto.Share) (func() error, error) { called = true; return nil, nil }}
	if err := m.prepare(); err != nil {
		t.Fatal(err)
	}
	j.fail = true
	r := m.mount(&guestproto.Share{ID: "share", Generation: 1, Path: filepath.Join(t.TempDir(), "mount"), Transport: "smb-tcp", Source: "source"})
	if called || r.ErrorCode != "recovery_required" {
		t.Fatalf("mount: %+v called=%v", r, called)
	}
}
