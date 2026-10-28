//go:build windows

package main

import (
	"errors"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
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
