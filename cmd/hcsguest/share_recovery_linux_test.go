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
	oldStart := shareUnprivilegedPortStart
	shareUnprivilegedPortStart = func() (uint32, error) { return 1024, nil }
	t.Cleanup(func() { shareUnprivilegedPortStart = oldStart })
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
	reserved, err := newShareRelay(1234)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(reserved.port())
	reserved.close()
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
	l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("relay still open: %v", err)
	}
	l.Close()
}

func TestRecoveryBusyRelayStillAllowsOwnedUnmount(t *testing.T) {
	oldStart := shareUnprivilegedPortStart
	shareUnprivilegedPortStart = func() (uint32, error) { return 1024, nil }
	t.Cleanup(func() { shareUnprivilegedPortStart = oldStart })
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
	reserved, err := newShareRelay(1234)
	if err != nil {
		t.Fatal(err)
	}
	defer reserved.close()
	r := shareIntent{Path: path, State: "mounted", MountID: 2, Transport: "smb-hvsocket", Port: 1234, RelayPort: uint16(reserved.port())}
	cleanup, err := recoverShareIntent(r)
	if err == nil || cleanup == nil {
		t.Fatal("expected relay error and safe cleanup")
	}
	shareUnmount = func(string, int) error { return nil }
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryMountMismatchDoesNotBindRelay(t *testing.T) {
	oldID, oldTrust, oldStart := shareMountID, shareTrustedDirectory, shareUnprivilegedPortStart
	t.Cleanup(func() { shareMountID, shareTrustedDirectory, shareUnprivilegedPortStart = oldID, oldTrust, oldStart })
	shareTrustedDirectory = func(int) error { return nil }
	shareUnprivilegedPortStart = func() (uint32, error) { return 1024, nil }
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
			return 3, nil
		}
		return 1, nil
	}
	r, err := newShareRelay(1234)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(r.port())
	r.close()
	cleanup, err := recoverShareIntent(shareIntent{Path: path, State: "mounted", MountID: 2, Transport: "smb-hvsocket", Port: 1234, RelayPort: port})
	if err == nil || cleanup != nil {
		t.Fatal("replaced mount accepted")
	}
	l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("port unexpectedly bound: %v", err)
	}
	l.Close()
}

func TestRelayRejectsUnprotectedPorts(t *testing.T) {
	old := shareUnprivilegedPortStart
	t.Cleanup(func() { shareUnprivilegedPortStart = old })
	shareUnprivilegedPortStart = func() (uint32, error) { return 0, nil }
	if _, err := newShareRelay(1234); err == nil {
		t.Fatal("unprotected pool accepted")
	}
	if _, err := newShareRelayAt(1234, 950); err == nil {
		t.Fatal("unprotected recovered port accepted")
	}
}

func TestStartupRestoresRelayWithoutShareRequest(t *testing.T) {
	oldID, oldTrust, oldStart, oldUnmount := shareMountID, shareTrustedDirectory, shareUnprivilegedPortStart, shareUnmount
	t.Cleanup(func() {
		shareMountID, shareTrustedDirectory, shareUnprivilegedPortStart, shareUnmount = oldID, oldTrust, oldStart, oldUnmount
	})
	shareTrustedDirectory = func(int) error { return nil }
	shareUnprivilegedPortStart = func() (uint32, error) { return 1024, nil }
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
	r, err := newShareRelay(1234)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(r.port())
	r.close()
	const boot = "12345678-1234-4123-8123-123456789abc"
	j := &memoryShareJournal{records: []shareIntent{{BootID: boot, ID: "share", Generation: 1, Path: path, Source: `\\server\share`, Transport: "smb-hvsocket", Port: 1234, RelayPort: port, MountID: 2, State: "mounted"}}}
	m := shareManager{journal: j, bootID: func() (string, error) { return boot, nil }, recoverBatch: recoverShareBatch}
	if err := m.recoverAtStartup(); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("relay not restored at startup: %v", err)
	}
	c.Close()
	shareUnmount = func(string, int) error { return nil }
	if err := m.entries["share"].cleanup(); err != nil {
		t.Fatal(err)
	}
}
