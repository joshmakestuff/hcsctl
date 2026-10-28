//go:build windows

package main

import (
	"errors"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"strings"
	"testing"
)

func TestGlobalLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		failAdd, failLink, failRemove bool
	}{
		{name: "add fails", failAdd: true}, {name: "link fails", failLink: true}, {name: "remove retry", failRemove: true}, {name: "shared mapping"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adds, removes, links, unlinks := 0, 0, 0, 0
			m := globalManager{ops: globalOps{
				command: func(r globalRequest) error {
					if r.Op == "add" {
						adds++
						if tc.failAdd {
							return errors.New("secret")
						}
					} else {
						removes++
						if tc.failRemove {
							tc.failRemove = false
							return errors.New("busy")
						}
					}
					return nil
				},
				link: func(_, _ string) error {
					links++
					if tc.failLink {
						return errors.New("failed")
					}
					return nil
				},
				removeLink: func(_, _ string) error { unlinks++; return nil },
			}}
			s := &guestproto.Share{Source: `\\server\share`, Path: `C:\x`, User: "user", Password: "secret"}
			cleanup, err := m.mount(s)
			if tc.failAdd {
				if err == nil || adds != 1 || removes != 0 || links != 0 {
					t.Fatalf("add failure: %v %d %d %d", err, adds, removes, links)
				}
				return
			}
			if tc.failLink {
				if err == nil || removes != 1 {
					t.Fatalf("rollback: %v %d", err, removes)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "shared mapping" {
				s2 := *s
				s2.Path = `C:\y`
				c2, e := m.mount(&s2)
				if e != nil {
					t.Fatal(e)
				}
				if e = cleanup(); e != nil || removes != 0 {
					t.Fatalf("first cleanup: %v %d", e, removes)
				}
				if e = c2(); e != nil {
					t.Fatal(e)
				}
				if adds != 1 || removes != 1 || unlinks != 2 {
					t.Fatal(adds, removes, unlinks)
				}
				return
			}
			if err = cleanup(); !errors.Is(err, errShareBusy) {
				t.Fatalf("expected busy: %v", err)
			}
			if err = cleanup(); err != nil || unlinks != 1 || removes != 2 {
				t.Fatalf("retry: %v %d %d", err, unlinks, removes)
			}
		})
	}
}

func TestGlobalAmbiguousCreationRetainsOwnership(t *testing.T) {
	var owned globalRequest
	exists := false
	calls := 0
	m := globalManager{ops: globalOps{
		command: func(r globalRequest) error {
			calls++
			if r.Op == "add" {
				owned = r
				exists = true
				return errors.New("ambiguous timeout or stderr")
			}
			if r.Token != owned.Token || r.Key != owned.Key || r.Remote != owned.Remote || r.User != owned.User || r.Port != owned.Port {
				return errors.New("ownership mismatch")
			}
			exists = false
			return nil
		},
		link: func(_, _ string) error { return nil }, removeLink: func(_, _ string) error { return nil },
	}}
	s := &guestproto.Share{Source: `\\server\share`, Path: `C:\x`, User: "guest", Password: "secret", Port: 445}
	if _, err := m.mount(s); err == nil || !exists {
		t.Fatal("ambiguous creation not retained")
	}
	e := m.entries[strings.ToLower(s.Source)]
	if e == nil || !e.pending || e.owner.Token == "" || e.owner.Password != "" {
		t.Fatal("ownership not retained safely")
	}
	// A second mount reconciles the previous owned mapping before creating anew.
	cleanup, err := m.mount(s)
	if err == nil || cleanup != nil || calls != 3 {
		t.Fatalf("expected second ambiguous add after reconcile: %v %d", err, calls)
	}
}

func TestGlobalReconcileRefusesMismatchAndRetriesAbsent(t *testing.T) {
	var owner globalRequest
	exists, mismatch := false, false
	removeCalls := 0
	m := globalManager{ops: globalOps{
		command: func(r globalRequest) error {
			if r.Op == "add" {
				owner = r
				exists = true
				return nil
			}
			removeCalls++
			if r.Token != owner.Token || mismatch {
				return errors.New("mismatched mapping")
			}
			if exists {
				exists = false
			}
			return nil
		}, link: func(_, _ string) error { return nil }, removeLink: func(_, _ string) error { return nil },
	}}
	s := &guestproto.Share{Source: `\\server\share`, Path: `C:\x`, User: "user", Password: "secret"}
	cleanup, err := m.mount(s)
	if err != nil {
		t.Fatal(err)
	}
	mismatch = true
	if err = cleanup(); !errors.Is(err, errShareBusy) || !exists {
		t.Fatal("mismatch should preserve mapping")
	}
	mismatch = false
	exists = false // External removal before retry is idempotent.
	if err = cleanup(); err != nil || removeCalls != 2 {
		t.Fatalf("absent retry: %v calls=%d", err, removeCalls)
	}
}

func TestGlobalIntentPersistedBeforeEffects(t *testing.T) {
	intent := &shareIntent{}
	persisted, effects := false, 0
	m := globalManager{ops: globalOps{
		command: func(r globalRequest) error {
			if r.Op == "add" {
				effects++
				if !persisted || intent.MappingToken != r.Token || intent.MappingKey != r.Key {
					t.Error("owner not journaled before mapping")
				}
			}
			return nil
		},
		link: func(_, _ string) error {
			effects++
			if !persisted {
				t.Error("owner not journaled before link")
			}
			return nil
		},
		linkIdentity:   func(_, _ string) (uint32, uint64, error) { return 4, 5, nil },
		verify:         func(globalRequest) error { return nil },
		removeIdentity: func(string, string, uint32, uint64) error { return nil },
	}}
	s := &guestproto.Share{Source: `\\server\share`, Path: `C:\x`, User: "guest", Password: "secret"}
	cleanup, err := m.mountIntent(s, intent, func() error { persisted = true; return nil })
	if err != nil || effects != 2 || intent.LinkVolume != 4 || intent.LinkIndex != 5 {
		t.Fatalf("mount: %v effects=%d intent=%+v", err, effects, intent)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	effects = 0
	_, err = m.mountIntent(s, &shareIntent{}, func() error { return errors.New("journal") })
	if !errors.Is(err, errShareJournal) || effects != 0 {
		t.Fatalf("journal failure: %v effects=%d", err, effects)
	}
}
