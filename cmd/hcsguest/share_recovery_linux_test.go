//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryRejectsReplacedMount(t *testing.T) {
	oldID, oldTrust, oldUnmount := shareMountID, shareTrustedDirectory, shareUnmount
	t.Cleanup(func() { shareMountID, shareTrustedDirectory, shareUnmount = oldID, oldTrust, oldUnmount })
	shareTrustedDirectory = func(int) error { return nil }
	path := filepath.Join(t.TempDir(), "mount")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	current := uint64(3)
	shareMountID = func(fd int) (uint64, error) {
		name, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil {
			return 0, err
		}
		if name == path {
			return current, nil
		}
		return 1, nil
	}
	called := false
	shareUnmount = func(string, int) error { called = true; return nil }
	r := shareIntent{Path: path, State: "mounted", MountID: 2}
	cleanup, err := recoverShareIntent(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err == nil || called {
		t.Fatal("removed replaced mount")
	}
	current = 2
	if err := cleanup(); err != nil || !called {
		t.Fatalf("owned cleanup: %v", err)
	}
}
