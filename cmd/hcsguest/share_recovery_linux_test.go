//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"golang.org/x/sys/unix"
)

func TestVirtioFSPendingRecovery(t *testing.T) {
	const boot = "12345678-1234-4123-8123-123456789abc"
	oldID, oldTrust, oldInfo, oldUnique := shareMountID, shareTrustedDirectory, readShareMountInfo, uniqueMountID
	t.Cleanup(func() {
		shareMountID, shareTrustedDirectory, readShareMountInfo, uniqueMountID = oldID, oldTrust, oldInfo, oldUnique
	})
	shareTrustedDirectory = func(int) error { return nil }
	path := filepath.Join(t.TempDir(), "mount")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	current := uint64(42)
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
	uniqueMountID = func(int) (uint64, error) { return 123, nil }
	readShareMountInfo = func() ([]byte, error) { return []byte("42 1 0:1 / /mnt ro - virtiofs tag1 rw\n"), nil }
	r := shareIntent{BootID: boot, ID: "share", Generation: 2, Path: path, Source: "tag1", Transport: "virtiofs", ReadOnly: true, MountID: 42, MountUniqueID: 123, TargetMountID: 1, TargetDevice: uint64(st.Dev), TargetInode: st.Ino, MountPhase: "attaching", State: "pending"}
	for _, tc := range []struct {
		name         string
		id           uint64
		phase, state string
	}{
		{"after move", 42, "attaching", "mounted"}, {"before move", 1, "attaching", "absent"}, {"after unmount", 1, "detaching", "absent"}, {"foreign mount", 55, "detaching", "recovery_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current = tc.id
			rec := r
			rec.MountPhase = tc.phase
			j := &memoryShareJournal{records: []shareIntent{rec}}
			m := shareManager{journal: j, bootID: func() (string, error) { return boot, nil }, recoverBatch: recoverShareBatch}
			if err := m.recoverAtStartup(); err != nil {
				t.Fatal(err)
			}
			got := m.status(&guestproto.ShareRef{ID: "share", Generation: 2, BootID: boot})
			if got.State != tc.state || j.records[0].State != map[string]string{"mounted": "mounted", "absent": "absent", "recovery_required": "pending"}[tc.state] {
				t.Fatalf("result=%+v journal=%+v", got, j.records)
			}
		})
	}
}

func TestVirtioFSAgentRestartIdentity(t *testing.T) {
	const boot = "12345678-1234-4123-8123-123456789abc"
	oldID, oldTrust, oldUnmount, oldInfo, oldUnique := shareMountID, shareTrustedDirectory, shareUnmount, readShareMountInfo, uniqueMountID
	t.Cleanup(func() {
		shareMountID, shareTrustedDirectory, shareUnmount, readShareMountInfo, uniqueMountID = oldID, oldTrust, oldUnmount, oldInfo, oldUnique
	})
	unique := uint64(123)
	uniqueMountID = func(int) (uint64, error) { return unique, nil }
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
			return 42, nil
		}
		return 1, nil
	}
	info := "42 1 0:1 / /mnt ro - virtiofs tag1 rw\n"
	readShareMountInfo = func() ([]byte, error) { return []byte(info), nil }
	called := 0
	busy := true
	shareUnmount = func(_ string, flags int) error {
		if flags != 0 {
			t.Fatal("forced unmount")
		}
		called++
		if busy {
			return unix.EBUSY
		}
		return nil
	}
	var target unix.Stat_t
	if err := unix.Stat(path, &target); err != nil {
		t.Fatal(err)
	}
	r := shareIntent{BootID: boot, ID: "share", Generation: 2, Path: path, Source: "tag1", Transport: "virtiofs", ReadOnly: true, MountID: 42, MountUniqueID: 123, TargetMountID: 1, TargetDevice: uint64(target.Dev), TargetInode: target.Ino, State: "mounted"}
	j := &memoryShareJournal{records: []shareIntent{r}}
	m := shareManager{journal: j, bootID: func() (string, error) { return boot, nil }, recoverBatch: recoverShareBatch}
	if err := m.recoverAtStartup(); err != nil {
		t.Fatal(err)
	}
	ref := &guestproto.ShareRef{ID: r.ID, Generation: r.Generation, BootID: boot}
	if result := m.status(ref); !result.OK || result.State != "mounted" {
		t.Fatalf("recovery: %+v", result)
	}
	info = "42 1 0:1 / /mnt ro - virtiofs foreign rw\n"
	if result := m.unmount(ref); result.OK || called != 0 {
		t.Fatalf("foreign mount: %+v", result)
	}
	info = "42 1 0:1 / /mnt ro - virtiofs tag1 rw\n"
	unique = 124
	if result := m.unmount(ref); result.OK || called != 0 {
		t.Fatalf("reused legacy mount ID: %+v", result)
	}
	unique = 123
	if result := m.unmount(ref); result.OK || result.ErrorCode != "busy" || result.State != "mounted" || called != 1 || j.records[0].State != "pending" || j.records[0].MountPhase != "detaching" {
		t.Fatalf("busy unmount: %+v calls=%d journal=%+v", result, called, j.records)
	}
	// Restart between the busy failure and retry: the mount is still owned.
	m = shareManager{journal: j, bootID: m.bootID, recoverBatch: recoverShareBatch}
	if err := m.recoverAtStartup(); err != nil {
		t.Fatal(err)
	}
	busy = false
	if result := m.unmount(ref); !result.OK || called != 2 {
		t.Fatalf("owned mount: %+v calls=%d", result, called)
	}
}

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
