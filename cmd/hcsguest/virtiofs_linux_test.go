//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"golang.org/x/sys/unix"
)

func TestLinuxCapabilities(t *testing.T) {
	files := map[string]string{"/proc/filesystems": "nodev\tvirtiofs\n", "/sys/bus/vmbus/drivers/hv_pci/swiotlb_base": "0x1000\n", "/sys/bus/vmbus/drivers/hv_pci/swiotlb_size": "67108864\n"}
	read := func(p string) ([]byte, error) {
		v, ok := files[p]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(v), nil
	}
	probe := func() bool { return true }
	c := linuxCapabilities(read, probe)
	if c.Version != 1 || !c.VirtioFS || !c.VirtioFSManaged || c.HvPciSwiotlb == nil || c.HvPciSwiotlb.Base != 4096 || c.HvPciSwiotlb.Size != 67108864 {
		t.Fatalf("bad capability: %+v", c)
	}
	files["/sys/bus/vmbus/drivers/hv_pci/swiotlb_base"] = "bogus"
	if linuxCapabilities(read, probe).HvPciSwiotlb != nil {
		t.Fatal("invalid pool was reported")
	}
	files["/sys/bus/vmbus/drivers/hv_pci/swiotlb_base"] = "0"
	files["/sys/bus/vmbus/drivers/hv_pci/swiotlb_size"] = "0"
	if p := linuxCapabilities(read, probe).HvPciSwiotlb; p == nil || p.Base != 0 || p.Size != 0 {
		t.Fatal("zero pool lost")
	}
	if c := linuxCapabilities(read, func() bool { return false }); !c.VirtioFS || c.VirtioFSManaged {
		t.Fatal("filesystem support confused with managed prerequisites")
	}
}

func TestProbeVirtioFSManaged(t *testing.T) {
	oldOpen, oldUnique := fsOpen, uniqueMountID
	t.Cleanup(func() { fsOpen, uniqueMountID = oldOpen, oldUnique })
	uniqueMountID = func(int) (uint64, error) { return 99, nil }
	fsOpen = func(string, int) (int, error) { return unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0) }
	if !probeVirtioFSManaged() {
		t.Fatal("supported probes rejected")
	}
	fsOpen = func(string, int) (int, error) { return -1, unix.EPERM }
	if probeVirtioFSManaged() {
		t.Fatal("denied fsopen accepted")
	}
	uniqueMountID = func(int) (uint64, error) { return 0, unix.EINVAL }
	fsOpen = func(string, int) (int, error) { t.Fatal("fsopen after identity failure"); return -1, nil }
	if probeVirtioFSManaged() {
		t.Fatal("missing identity accepted")
	}
}

func TestVirtioFSMountIdentity(t *testing.T) {
	r := &shareIntent{Source: "tag1", ReadOnly: true}
	for _, tc := range []struct {
		name, line string
		id         uint64
		ok         bool
	}{
		{"matching", "42 1 0:1 / /mnt ro,nosuid - virtiofs tag1 rw", 42, true},
		{"foreign tag", "42 1 0:1 / /mnt ro - virtiofs tag2 rw", 42, false},
		{"wrong identity", "42 1 0:1 / /mnt ro - virtiofs tag1 rw", 43, false},
		{"writable", "42 1 0:1 / /mnt rw - virtiofs tag1 rw", 42, false},
		{"foreign filesystem", "42 1 0:1 / /mnt ro - tmpfs tag1 rw", 42, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (matchVirtioFSMount(tc.line, r, tc.id) == nil) != tc.ok {
				t.Fatal("unexpected identity result")
			}
		})
	}
}

func TestVirtioFSMountFlagsAndErrors(t *testing.T) {
	open, set, create, mount, move, unique, id := fsOpen, fsSetString, fsCreate, fsMount, fsMoveMount, uniqueMountID, shareMountID
	t.Cleanup(func() {
		fsOpen, fsSetString, fsCreate, fsMount, fsMoveMount, uniqueMountID, shareMountID = open, set, create, mount, move, unique, id
	})
	fsOpen = func(name string, flags int) (int, error) {
		if name != "virtiofs" {
			t.Fatal(name)
		}
		return unix.Open("/dev/null", unix.O_RDONLY, 0)
	}
	fsSetString = func(_ int, key, value string) error {
		if key != "source" || value != "tag1" {
			t.Fatal("source")
		}
		return nil
	}
	fsCreate = func(int) error { return nil }
	fsMount = func(_ int, _ int, flags int) (int, error) {
		if flags != unix.MOUNT_ATTR_RDONLY {
			t.Fatal("RO missing")
		}
		return unix.Open("/dev/null", unix.O_RDONLY, 0)
	}
	uniqueMountID = func(int) (uint64, error) { return 123, nil }
	shareMountID = func(int) (uint64, error) { return 42, nil }
	moved := false
	fsMoveMount = func(int, string, int, string, int) error { moved = true; return unix.EINVAL }
	s := &guestproto.Share{Source: "tag1", ReadOnly: true}
	r := &shareIntent{}
	_, err := mountVirtioFSDetached(s, r, func() error { return errors.New("disk") }, 0, unix.Stat_t{Ino: 9}, 1)
	if !errors.Is(err, errShareJournal) || moved {
		t.Fatalf("move before journal: %v", err)
	}
	_, err = mountVirtioFSDetached(s, r, func() error {
		if r.MountUniqueID != 123 || r.MountID != 42 || r.MountPhase != "attaching" {
			t.Fatal("identity not persisted before move")
		}
		return nil
	}, 0, unix.Stat_t{Ino: 9}, 1)
	if !moved || !errors.Is(err, unix.EINVAL) || errors.Is(err, errShareTransportUnavailable) {
		t.Fatalf("unexpected move failure: %v", err)
	}
	for _, errno := range []error{unix.EINVAL, unix.EACCES, unix.EPERM} {
		fsCreate = func(int) error { return errno }
		_, err := mountVirtioFSDetached(s, &shareIntent{}, func() error { return nil }, 0, unix.Stat_t{Ino: 9}, 1)
		if !errors.Is(err, errno) || errors.Is(err, errShareTransportUnavailable) || errors.Is(err, errSharePrerequisiteMissing) {
			t.Fatalf("fsconfig create %v misclassified: %v", errno, err)
		}
	}
}

func TestVirtioFSTagDiscovery(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "7"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "7", "tag"), []byte("tag1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, dir, tag string
		present, known bool
	}{
		{"present", dir, "tag1", true, true},
		{"absent", dir, "tag2", false, true},
		{"no interface", filepath.Join(dir, "missing"), "tag1", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, k, err := virtioFSTagPresent(tc.dir, tc.tag)
			if err != nil || p != tc.present || k != tc.known {
				t.Fatalf("present=%v known=%v error=%v", p, k, err)
			}
		})
	}
}
