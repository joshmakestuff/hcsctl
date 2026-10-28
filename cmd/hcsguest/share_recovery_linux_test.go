//go:build linux

package main

import (
	"fmt"
	"net"
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
	current := uint64(2)
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
	current = 3
	if err := cleanup(); err == nil || called {
		t.Fatal("removed replaced mount")
	}
	current = 2
	if err := cleanup(); err != nil || !called {
		t.Fatalf("owned cleanup: %v", err)
	}
}

func TestRecoveryRestoresRelayAndValidatesMount(t *testing.T) {
	oldID, oldTrust, oldUnmount := shareMountID, shareTrustedDirectory, shareUnmount
	t.Cleanup(func() { shareMountID, shareTrustedDirectory, shareUnmount = oldID, oldTrust, oldUnmount })
	shareTrustedDirectory = func(int) error { return nil }
	path := filepath.Join(t.TempDir(), "mount")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	shareMountID = func(fd int) (uint64, error) {
		name, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil {
			return 0, err
		}
		if name == path {
			return 2, nil
		}
		return 1, nil
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	r := shareIntent{Path: path, State: "mounted", MountID: 2, Transport: "smb-hvsocket", Port: 1234, RelayPort: port}
	cleanup, err := recoverShareIntent(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
		t.Fatal("relay port not restored")
	}
	shareUnmount = func(string, int) error { return nil }
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	l, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("relay still open: %v", err)
	}
	l.Close()
}

func TestRecoveryBusyRelayStillAllowsOwnedUnmount(t *testing.T) {
	oldID, oldTrust, oldUnmount := shareMountID, shareTrustedDirectory, shareUnmount
	t.Cleanup(func() { shareMountID, shareTrustedDirectory, shareUnmount = oldID, oldTrust, oldUnmount })
	shareTrustedDirectory = func(int) error { return nil }
	path := filepath.Join(t.TempDir(), "mount")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	shareMountID = func(fd int) (uint64, error) {
		name, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil {
			return 0, err
		}
		if name == path {
			return 2, nil
		}
		return 1, nil
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r := shareIntent{Path: path, State: "mounted", MountID: 2, Transport: "smb-hvsocket", Port: 1234, RelayPort: uint16(l.Addr().(*net.TCPAddr).Port)}
	cleanup, err := recoverShareIntent(r)
	if err == nil || cleanup == nil {
		t.Fatal("expected relay error and safe cleanup")
	}
	shareUnmount = func(string, int) error { return nil }
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
}
