//go:build windows

// Package storage is the `hcsctl storage` verb group: the computestorage layer surface --
// VHD-backed writable layers presented through the container storage filter (wcifs).
//
// This is a different layer *format* from the wclayer directory layers the other verb groups
// use, not a second route to the same place -- see issue #12 for the decision and #18 for the
// surface. The verbs mirror the sequence measured in hcsspike/probes/computestorage:
//
//	setup-base  create + format blank-base.vhdx -> SetupBaseOSLayer -> diff blank.vhdx
//	mount       copy blank.vhdx -> sandbox.vhdx, attach, InitializeWritableLayer,
//	            AttachLayerStorageFilter -> volume path with the merged view
//	unmount     DetachLayerStorageFilter, detach the VHD
//
// Verbs take explicit directory paths rather than store refs: SetupBaseOSLayer regenerates
// Hives/ and Layout inside the layer directory it is given, and whether the regenerated
// hives are equivalent to what wclayer import produced is not yet measured -- so these verbs
// do not touch store layers until that is established.
//
// ELEVATED: FormatWritableLayerVhd is denied from a filtered token even holding
// SeManageVolumePrivilege (measured, findings.md).
package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Microsoft/go-winio/vhd"
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/computestorage"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"golang.org/x/sys/windows"
)

func Dispatch(a *cli.Args, e cli.Emit) (int, error) {
	switch a.Word(1) {
	case "setup-base":
		return setupBase(a, e)
	case "mount":
		return mount(a, e)
	case "unmount":
		return unmount(a, e)
	case "":
		return cli.Usage, cli.Usagef("storage needs a subcommand: setup-base, mount, unmount")
	default:
		return cli.Usage, cli.Usagef("unknown storage subcommand %q (expected setup-base, mount, unmount)", a.Word(1))
	}
}

const (
	blankBaseName = "blank-base.vhdx"
	blankName     = "blank.vhdx"
	sandboxName   = "sandbox.vhdx"
	defaultSizeGB = 10
)

// requireDir is the shared argument shape: a named option that must be an existing directory.
func requireDir(a *cli.Args, name string) (string, error) {
	v, err := a.Require(name)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(v)
	if err != nil {
		return "", cli.Usagef("%s %s: %v", name, v, err)
	}
	if !fi.IsDir() {
		return "", cli.Usagef("%s %s is not a directory", name, v)
	}
	return v, nil
}

func setupBase(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--layer", "--size-gb"); err != nil {
		return cli.Usage, err
	}
	layer, err := requireDir(a, "--layer")
	if err != nil {
		return cli.Usage, err
	}
	size := uint64(defaultSizeGB)
	if v := a.Option("--size-gb"); v != "" {
		if size, err = parseUint(v); err != nil {
			return cli.Usage, cli.Usagef("--size-gb must be a positive integer, got %q", v)
		}
	}
	// The layer must look like a layer before SetupBaseOSLayer deletes anything from it: the
	// verb mutates its input (regenerates Hives/ and Layout), and pointing it at an arbitrary
	// directory should fail before the mutation, not after.
	if _, err := os.Stat(filepath.Join(layer, "Files")); err != nil {
		return cli.Usage, cli.Usagef("--layer %s has no Files directory -- not a materialized layer", layer)
	}

	base := filepath.Join(layer, blankBaseName)
	diff := filepath.Join(layer, blankName)
	e.Progress("SetupContainerBaseLayer: %s (%d GB) -- regenerates Hives/ and Layout in the layer", layer, size)
	if err := computestorage.SetupContainerBaseLayer(context.Background(), layer, base, diff, size); err != nil {
		return cli.Failed, fmt.Errorf("SetupContainerBaseLayer: %w", err)
	}

	e.Result(map[string]any{
		"ok": true, "command": "storage setup-base", "layer": layer,
		"baseVhd": base, "diffVhd": diff, "sizeGB": size,
	}, func() {
		fmt.Printf("base ready\n  blank-base: %s\n  blank:      %s\n", base, diff)
	})
	return cli.OK, nil
}

// openScratch opens sandbox.vhdx in dir. Access/flags per the probe: AccessNone + no flags is
// what both attach and mount-path retrieval want on V2 VHDX.
func openScratch(dir string) (syscall.Handle, string, error) {
	p := filepath.Join(dir, sandboxName)
	if _, err := os.Stat(p); err != nil {
		return 0, p, cli.Usagef("no %s in %s -- run storage mount with --base first", sandboxName, dir)
	}
	h, err := vhd.OpenVirtualDisk(p, vhd.VirtualDiskAccessNone, vhd.OpenVirtualDiskFlagNone)
	if err != nil {
		return 0, p, fmt.Errorf("OpenVirtualDisk(%s): %w", p, err)
	}
	return h, p, nil
}

func mount(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--base", "--scratch-dir", "--parent"); err != nil {
		return cli.Usage, err
	}
	base, err := requireDir(a, "--base")
	if err != nil {
		return cli.Usage, err
	}
	dir, err := a.Require("--scratch-dir")
	if err != nil {
		return cli.Usage, err
	}
	parents := a.Options("--parent")
	if len(parents) == 0 {
		parents = []string{base}
	}
	for _, p := range parents {
		if _, err := os.Stat(p); err != nil {
			return cli.Usage, cli.Usagef("--parent %s: %v", p, err)
		}
	}
	blank := filepath.Join(base, blankName)
	if _, err := os.Stat(blank); err != nil {
		return cli.Usage, cli.Usagef("%s has no %s -- run storage setup-base first", base, blankName)
	}

	var layers []computestorage.Layer
	for _, p := range parents {
		g, err := hcsshim.NameToGuid(filepath.Base(p))
		if err != nil {
			return cli.Failed, fmt.Errorf("NameToGuid(%s): %w", filepath.Base(p), err)
		}
		layers = append(layers, computestorage.Layer{Id: g.ToString(), Path: p, PathType: "AbsolutePath"})
	}
	data := computestorage.LayerData{
		SchemaVersion: computestorage.Version{Major: 2, Minor: 1},
		Layers:        layers,
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return cli.Failed, err
	}
	sandbox := filepath.Join(dir, sandboxName)
	fresh := false
	if _, err := os.Stat(sandbox); err != nil {
		if err := copyFile(blank, sandbox); err != nil {
			return cli.Failed, fmt.Errorf("copy %s -> %s: %w", blank, sandbox, err)
		}
		fresh = true
		e.Progress("scratch:   %s (fresh from %s)", sandbox, blankName)
	} else {
		e.Progress("scratch:   %s (existing, not reinitialized)", sandbox)
	}

	h, err := vhd.OpenVirtualDisk(sandbox, vhd.VirtualDiskAccessNone, vhd.OpenVirtualDiskFlagNone)
	if err != nil {
		return cli.Failed, fmt.Errorf("OpenVirtualDisk(%s): %w", sandbox, err)
	}
	defer syscall.CloseHandle(h)

	// PermanentLifetime: the mount must outlive this process, same as layer mount's
	// ActivateLayer does. Without it the volume vanishes when the handle closes.
	ctx := context.Background()
	if err := vhd.AttachVirtualDisk(h, vhd.AttachVirtualDiskFlagPermanentLifetime,
		&vhd.AttachVirtualDiskParameters{Version: 2}); err != nil {
		return cli.Failed, fmt.Errorf("AttachVirtualDisk: %w", err)
	}
	undo := func() {
		_ = vhd.DetachVirtualDisk(h)
		if fresh {
			os.Remove(sandbox)
		}
	}

	vol, err := computestorage.GetLayerVhdMountPath(ctx, windows.Handle(h))
	if err != nil {
		undo()
		return cli.Failed, fmt.Errorf("GetLayerVhdMountPath: %w", err)
	}
	e.Progress("volume:    %s", vol)

	if fresh {
		if err := computestorage.InitializeWritableLayer(ctx, vol, data); err != nil {
			undo()
			return cli.Failed, fmt.Errorf("InitializeWritableLayer: %w", err)
		}
		e.Progress("InitializeWritableLayer ok")
	}
	if err := computestorage.AttachLayerStorageFilter(ctx, vol, data); err != nil {
		undo()
		return cli.Failed, fmt.Errorf("AttachLayerStorageFilter: %w", err)
	}

	e.Result(map[string]any{
		"ok": true, "command": "storage mount", "scratch": sandbox,
		"volume": vol, "parents": parents, "fresh": fresh,
	}, func() {
		fmt.Printf("mounted\n  scratch: %s\n  volume:  %s\n", sandbox, vol)
	})
	return cli.OK, nil
}

func unmount(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--scratch-dir"); err != nil {
		return cli.Usage, err
	}
	dir, err := a.Require("--scratch-dir")
	if err != nil {
		return cli.Usage, err
	}
	h, sandbox, err := openScratch(dir)
	if err != nil {
		return exitFor(err), err
	}
	defer syscall.CloseHandle(h)
	ctx := context.Background()

	// Both steps are attempted regardless of earlier failures, same shape as container
	// teardown: a half-unmounted scratch should lose as much as possible.
	var first error
	if vol, err := computestorage.GetLayerVhdMountPath(ctx, windows.Handle(h)); err == nil {
		if err := computestorage.DetachLayerStorageFilter(ctx, vol); err != nil {
			first = fmt.Errorf("DetachLayerStorageFilter: %w", err)
			e.Progress("%v -- detaching disk anyway", first)
		} else {
			e.Progress("filter detached")
		}
	} else {
		first = fmt.Errorf("GetLayerVhdMountPath (already detached?): %w", err)
		e.Progress("%v", first)
	}
	if err := vhd.DetachVirtualDisk(h); err != nil && first == nil {
		first = fmt.Errorf("DetachVirtualDisk: %w", err)
	}
	if first != nil {
		return cli.Failed, first
	}

	e.Result(map[string]any{
		"ok": true, "command": "storage unmount", "scratch": sandbox,
	}, func() {
		fmt.Printf("unmounted %s\n", sandbox)
	})
	return cli.OK, nil
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

func parseUint(s string) (uint64, error) {
	var n uint64
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + uint64(c-'0')
	}
	if n == 0 {
		return 0, fmt.Errorf("zero")
	}
	return n, nil
}

func exitFor(err error) int {
	if _, ok := err.(*cli.UsageError); ok {
		return cli.Usage
	}
	return cli.Failed
}
