package main

import (
	"errors"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

func TestParseBootID(t *testing.T) {
	for _, s := range []string{"", "00000000-0000-0000-0000-000000000000", "bogus", "12345678-1234-4123-8123-123456789abg"} {
		if _, err := parseBootID(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	id, err := newBootID()
	if err != nil || !validBootID(id) {
		t.Fatalf("new boot id %q: %v", id, err)
	}
	if got, err := parseBootID(id + "\n"); err != nil || got != id {
		t.Fatalf("parse %q: %v", got, err)
	}
}

func TestShareFailsClosedWithoutBootID(t *testing.T) {
	called := false
	m := shareManager{bootID: func() (string, error) { return "", errors.New("unavailable") }, backend: func(*guestproto.Share) (func() error, error) { called = true; return nil, nil }}
	if r := m.mount(&guestproto.Share{}); r.OK || r.ErrorCode != "boot_id_unavailable" || called {
		t.Fatalf("mount: %+v called=%v", r, called)
	}
	if r := m.status(nil); r.OK || r.ErrorCode != "boot_id_unavailable" {
		t.Fatalf("status: %+v", r)
	}
	if r := m.unmount(nil); r.OK || r.ErrorCode != "boot_id_unavailable" {
		t.Fatalf("unmount: %+v", r)
	}
}
