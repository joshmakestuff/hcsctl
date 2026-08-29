//go:build windows

// Package scratch produces and tears down container writable layers on the
// computestorage path -- the one scratch shape in this tool. A scratch is a
// sandbox.vhdx (copied from the base layer's blank.vhdx), initialized as a
// writable layer; isolation decides presentation:
//
//   - argon: the VHD stays attached (permanent lifetime) with the layer
//     storage filter on its volume, and the volume path goes into the v2
//     document's Container.Storage.Path. The filter attach is the caller's
//     job -- HCS does not attach it from the document; Start fails 0x80070287
//     without it.
//   - xenon: the VHD is initialized then detached -- the schema-1 document
//     consumes the scratch DIRECTORY, and the layers stack in-guest.
//
// Every sandbox gets the Virtual Machines group ACE: a xenon opens the VHD
// under S-1-5-83-0 at create and is refused without it;
// an argon is unharmed by it.
package scratch

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Microsoft/go-winio/vhd"
	"github.com/Microsoft/hcsshim/computestorage"
	"github.com/joshmakestuff/hcsctl/internal/layerid"
	"golang.org/x/sys/windows"
)

const (
	blankName   = "blank.vhdx"
	sandboxName = "sandbox.vhdx"
)

// Scratch describes a prepared writable layer.
type Scratch struct {
	Dir     string // the scratch directory
	Sandbox string // <Dir>\sandbox.vhdx
	// Volume is the mounted volume path with its trailing backslash -- the
	// exact string a v2 document's Container.Storage.Path takes. Empty for a
	// xenon scratch (detached).
	Volume string
}

// Prepare makes the scratch for a container over chainTopFirst (topmost
// first; the base is the last entry). size, when non-zero, grows the sandbox
// to at least that many bytes before attach. attachFilter selects the argon
// presentation (attached volume + storage filter); false detaches for xenon.
//
// Idempotent over an existing sandbox.vhdx: the copy and InitializeWritableLayer
// are skipped, the attach and filter are redone -- restart after a reboot
// reuses the written scratch.
func Prepare(scratchDir string, chainTopFirst []string, size uint64, attachFilter bool) (*Scratch, error) {
	if len(chainTopFirst) == 0 {
		return nil, fmt.Errorf("empty layer chain")
	}
	base := chainTopFirst[len(chainTopFirst)-1]
	blank := filepath.Join(base, blankName)
	if _, err := os.Stat(blank); err != nil {
		return nil, fmt.Errorf("%s has no %s -- the base layer is not set up: %w", base, blankName, err)
	}
	data, err := layerid.DataFor(chainTopFirst)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		return nil, err
	}
	sandbox := filepath.Join(scratchDir, sandboxName)
	fresh := false
	if _, err := os.Stat(sandbox); err != nil {
		if err := copyFile(blank, sandbox); err != nil {
			return nil, fmt.Errorf("copy %s -> %s: %w", blank, sandbox, err)
		}
		fresh = true
	}
	if err := GrantVMGroupAccess(sandbox); err != nil {
		return nil, err
	}
	if fresh && size != 0 {
		// Between creation and attach, while nothing holds the VHD -- the
		// sequencing ExpandScratch requires.
		if err := ExpandScratch(scratchDir, size); err != nil {
			return nil, fmt.Errorf("ExpandScratch: %w", err)
		}
	}

	if !attachFilter {
		// Xenon: the document consumes the DIRECTORY and the utility VM
		// initializes the writable layer in-guest -- no host-side attach, no
		// InitializeWritableLayer (the blank.vhdx copy plus the VM-group ACE
		// is the complete scratch). This is also what keeps the xenon
		// unelevated: an unelevated attach yields no mount path (see below).
		return &Scratch{Dir: scratchDir, Sandbox: sandbox}, nil
	}

	h, err := vhd.OpenVirtualDisk(sandbox, vhd.VirtualDiskAccessNone, vhd.OpenVirtualDiskFlagNone)
	if err != nil {
		return nil, fmt.Errorf("OpenVirtualDisk(%s): %w", sandbox, err)
	}
	defer syscall.CloseHandle(h)

	ctx := context.Background()
	// PermanentLifetime: the attach must outlive this process for a container
	// started by a later invocation.
	if err := vhd.AttachVirtualDisk(h, vhd.AttachVirtualDiskFlagPermanentLifetime,
		&vhd.AttachVirtualDiskParameters{Version: 2}); err != nil {
		return nil, fmt.Errorf("AttachVirtualDisk: %w", err)
	}
	undo := func() {
		_ = vhd.DetachVirtualDisk(h)
		if fresh {
			_ = os.Remove(sandbox)
		}
	}

	vol, err := computestorage.GetLayerVhdMountPath(ctx, windows.Handle(h))
	if err != nil {
		undo()
		return nil, fmt.Errorf("GetLayerVhdMountPath: %w", err)
	}
	if vol == "" {
		// The attach succeeds unelevated but yields NO mount path -- the call
		// reports success with an empty string. Without the volume
		// there is nothing to initialize or filter.
		undo()
		return nil, fmt.Errorf("the attached scratch has no mount path -- an unelevated attach mounts no volume; process isolation needs elevation")
	}
	if vol[len(vol)-1] != '\\' {
		vol += `\`
	}
	if fresh {
		if err := computestorage.InitializeWritableLayer(ctx, vol, data); err != nil {
			undo()
			return nil, fmt.Errorf("InitializeWritableLayer: %w", err)
		}
	}

	if err := computestorage.AttachLayerStorageFilter(ctx, vol, data); err != nil {
		undo()
		return nil, fmt.Errorf("AttachLayerStorageFilter: %w", err)
	}
	return &Scratch{Dir: scratchDir, Sandbox: sandbox, Volume: vol}, nil
}

// Volume reopens an existing scratch's attached volume path (trailing
// backslash included) without changing any state -- for teardown and inspect
// from a later invocation.
func Volume(scratchDir string) (string, error) {
	h, err := vhd.OpenVirtualDisk(filepath.Join(scratchDir, sandboxName),
		vhd.VirtualDiskAccessNone, vhd.OpenVirtualDiskFlagNone)
	if err != nil {
		return "", fmt.Errorf("OpenVirtualDisk: %w", err)
	}
	defer syscall.CloseHandle(h)
	vol, err := computestorage.GetLayerVhdMountPath(context.Background(), windows.Handle(h))
	if err != nil {
		return "", fmt.Errorf("GetLayerVhdMountPath (not attached?): %w", err)
	}
	if vol[len(vol)-1] != '\\' {
		vol += `\`
	}
	return vol, nil
}

// detachRetries x detachInterval bounds the storage-filter detach: container
// teardown is asynchronous and the filter refuses while the volume is still in
// use ("Do not detach... at this time"), settling within seconds.
const (
	detachRetries  = 10
	detachInterval = time.Second
)

// Teardown releases and destroys a scratch. filtered says the argon
// presentation was (or may have been) active: detach the storage filter
// before the VHD. The VHD detach itself is attempted unconditionally -- a
// crashed create can leave a permanent attach behind with no filter, and
// DestroyLayer fails on a directory holding an attached VHD.
// Destruction is verified by absence -- DestroyLayer can report success and
// leave the tree.
func Teardown(scratchDir string, filtered bool) error {
	ctx := context.Background()
	sandbox := filepath.Join(scratchDir, sandboxName)
	if h, err := vhd.OpenVirtualDisk(sandbox, vhd.VirtualDiskAccessNone, vhd.OpenVirtualDiskFlagNone); err == nil {
		if filtered {
			if vol, verr := computestorage.GetLayerVhdMountPath(ctx, windows.Handle(h)); verr == nil && vol != "" {
				var derr error
				for i := 0; i < detachRetries; i++ {
					if derr = computestorage.DetachLayerStorageFilter(ctx, vol); derr == nil {
						break
					}
					time.Sleep(detachInterval)
				}
				if derr != nil {
					_ = syscall.CloseHandle(h)
					return fmt.Errorf("DetachLayerStorageFilter: %w", derr)
				}
			}
		}
		// Detach errors are ignored: a not-attached disk is the ordinary case.
		_ = vhd.DetachVirtualDisk(h)
		_ = syscall.CloseHandle(h)
	}
	if _, err := os.Stat(scratchDir); os.IsNotExist(err) {
		return nil
	}
	if err := computestorage.DestroyLayer(ctx, scratchDir); err != nil {
		return fmt.Errorf("DestroyLayer(%s): %w", scratchDir, err)
	}
	if _, err := os.Stat(scratchDir); err == nil {
		return fmt.Errorf("DestroyLayer reported success but %s still exists", scratchDir)
	}
	return nil
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()
	if _, err := io.Copy(d, s); err != nil {
		return err
	}
	return d.Sync()
}
