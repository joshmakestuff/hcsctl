//go:build windows

package vm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func record(t *testing.T, s *store.Store, id, base string, cow bool) {
	t.Helper()
	if err := writeState(s, state{ID: id, BaseVHDX: base, CopyOnWrite: cow,
		DiskPath: filepath.Join(vmDir(s, id), "disk.vhdx")}); err != nil {
		t.Fatal(err)
	}
}

// --no-copy-on-write writes to the image it is given, and a differencing child is only valid
// while its parent is unchanged. Nothing in the VHDX format enforces that, so the check has to
// be here or the mistake is silent and destroys every child.
func TestChildrenOfFindsDependentVMs(t *testing.T) {
	s := newStore(t)
	const base = `E:\images\rocky.vhdx`
	record(t, s, "child-1", base, true)
	record(t, s, "child-2", base, true)
	record(t, s, "unrelated", `E:\images\other.vhdx`, true)
	// A VM booting the image directly is not a child of it -- it has no differencing disk.
	record(t, s, "direct", base, false)

	got, err := childrenOf(s, base, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v, want the two differencing children", got)
	}
}

// A base attached via --disk has differencing children of its own, and booting it directly
// corrupts them the same way booting a boot-disk parent would.
func TestChildrenOfFindsDependentsViaExtraDisks(t *testing.T) {
	s := newStore(t)
	const base = `E:\images\data.vhdx`
	if err := writeState(s, state{ID: "with-data", BaseVHDX: `E:\images\os.vhdx`, CopyOnWrite: true,
		DiskPath:   filepath.Join(vmDir(s, "with-data"), "disk.vhdx"),
		ExtraDisks: []extraDisk{{Base: base, Path: filepath.Join(vmDir(s, "with-data"), "disk1.vhdx")}},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := childrenOf(s, base, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %v, want the VM whose extra disk is a child of the base", got)
	}
}

// Every disk in the chain needs the VHDX grant -- children and, under copy-on-write, their
// parents. A missing grant on any of them fails at start.
func TestGrantPathsCoverEveryDiskInTheChain(t *testing.T) {
	cow := state{CopyOnWrite: true,
		BaseVHDX: `E:\images\os.vhdx`, DiskPath: `E:\vms\x\disk.vhdx`,
		ExtraDisks: []extraDisk{{Base: `E:\images\data.vhdx`, Path: `E:\vms\x\disk1.vhdx`}},
	}
	if got := grantPaths(cow); len(got) != 4 {
		t.Errorf("copy-on-write: got %v, want both children and both parents", got)
	}
	direct := state{CopyOnWrite: false,
		BaseVHDX: `E:\images\os.vhdx`, DiskPath: `E:\images\os.vhdx`,
		ExtraDisks: []extraDisk{{Base: `E:\images\data.vhdx`, Path: `E:\images\data.vhdx`}},
	}
	if got := grantPaths(direct); len(got) != 2 {
		t.Errorf("direct: got %v, want the two images", got)
	}
}

// Case and separators must not be a way past the guard: E:\Images\X.vhdx and e:\images\x.vhdx
// are the same file on Windows.
func TestChildrenOfComparesPathsCaseInsensitively(t *testing.T) {
	s := newStore(t)
	record(t, s, "child", `E:\Images\Rocky.vhdx`, true)

	got, err := childrenOf(s, `e:\images\.\rocky.vhdx`, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %v, want the child -- the path differs only in case and cleanliness", got)
	}
}

// The VM being created has its directory made before the check runs, so it must not count
// itself.
func TestChildrenOfIgnoresTheVMBeingCreated(t *testing.T) {
	s := newStore(t)
	const base = `E:\images\rocky.vhdx`
	record(t, s, "self", base, true)

	got, err := childrenOf(s, base, "self")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want nothing", got)
	}
}

// A record that cannot be read cannot be shown to be safe. Skipping it would turn a corrupt
// file into permission to overwrite a disk, so it counts as a child.
func TestChildrenOfCountsAnUnreadableRecord(t *testing.T) {
	s := newStore(t)
	dir := vmDir(s, "broken")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := childrenOf(s, `E:\images\rocky.vhdx`, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %v, want the unreadable record counted", got)
	}
}

// An empty store is the ordinary first run, not an error.
func TestChildrenOfOnAnEmptyStore(t *testing.T) {
	got, err := childrenOf(newStore(t), `E:\images\rocky.vhdx`, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want nothing", got)
	}
}
