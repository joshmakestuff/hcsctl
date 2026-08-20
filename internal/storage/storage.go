//go:build windows

// Package storage is the `hcsctl storage` verb group: the computestorage layer surface --
// VHD-backed writable layers presented through the container storage filter (wcifs).
//
// This is a different layer format from the wclayer directory layers the other verb groups
// use. The verbs mirror the computestorage sequence:
//
//	setup-base  create + format blank-base.vhdx -> SetupBaseOSLayer -> diff blank.vhdx
//	mount       copy blank.vhdx -> sandbox.vhdx, attach, InitializeWritableLayer,
//	            AttachLayerStorageFilter -> volume path with the merged view
//	unmount     DetachLayerStorageFilter, detach the VHD
//
// Only mount accepts a store ref. SetupBaseOSLayer regenerates Hives/ and Layout inside the
// layer directory it is given, and whether the regenerated hives are equivalent to what
// wclayer import produced is not measured, so setup-base must not run on a store layer.
//
// ELEVATED: FormatWritableLayerVhd is denied from a filtered token even holding
// SeManageVolumePrivilege (measured).
package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	winio "github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/vhd"
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/computestorage"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/store"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

// Command is `hcsctl storage`.
func Command(e cli.Emit) *cobra.Command {
	return cli.Group("storage", "VHD-backed layers via computestorage",
		setupBaseCmd(e), mountCmd(e), unmountCmd(e), importCmd(e), exportCmd(e), destroyCmd(e))
}

func setupBaseCmd(e cli.Emit) *cobra.Command {
	var layer, sizeGB string
	cmd := &cobra.Command{
		Use:   "setup-base --layer <dir> [--size-gb N]",
		Short: "prepare a base layer for VHD-backed use. MUTATES the layer, ELEVATED",
		Long: `Prepare a base layer for VHD-backed (computestorage) use: blank-base.vhdx and
blank.vhdx created inside the layer directory. MUTATES the layer -- Hives/ and
Layout are regenerated -- so point it at a copy, not a store layer. ELEVATED.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := requireDir("--layer", layer); err != nil {
				return err
			}
			size := uint64(defaultSizeGB)
			if sizeGB != "" {
				// SetupContainerBaseLayer takes GB; 65536 GB is the VHDX format ceiling (64 TB).
				var err error
				if size, err = cli.ParseUint(sizeGB, 65536); err != nil {
					return cli.Usagef("--size-gb %v", err)
				}
			}
			// SetupBaseOSLayer mutates its input (regenerates Hives/ and Layout); the layer
			// check runs before the mutation.
			if _, err := os.Stat(filepath.Join(layer, "Files")); err != nil {
				return cli.Usagef("--layer %s has no Files directory -- not a materialized layer", layer)
			}
			return setupBase(layer, size, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &layer, "layer", "layer directory to prepare")
	cli.Required(cmd, "layer")
	cli.StringOnce(cmd.Flags(), &sizeGB, "size-gb", "base VHD size in GB (default 10)")
	return cmd
}

func mountCmd(e cli.Emit) *cobra.Command {
	var base, ref, storeDir, scratchDir string
	var parents []string
	cmd := &cobra.Command{
		Use:   "mount (--base <dir> | --ref <ref>) --scratch-dir <dir> [--parent <dir>]... [--store <dir>]",
		Short: "attach a writable scratch over a base and print the merged volume. ELEVATED",
		Long: `Copy blank.vhdx to sandbox.vhdx (first time), attach it, initialize the
writable layer and attach the storage filter. Prints the volume carrying the
merged view. Parents topmost first; defaults to the base. --ref resolves a
store image's chain instead -- store base layers already carry blank.vhdx
(wclayer import creates it), so nothing mutates the store. ELEVATED.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if ref != "" && base != "" {
				return cli.Usagef("--ref and --base are exclusive: a ref resolves the whole chain")
			}
			if ref == "" {
				if err := requireDir("--base", base); err != nil {
					return err
				}
				if err := checkParents(parents); err != nil {
					return err
				}
			}
			return mount(ref, base, storeDir, scratchDir, parents, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &base, "base", "base layer directory carrying blank.vhdx")
	cli.StringOnce(cmd.Flags(), &ref, "ref", "store image reference; resolves the whole chain")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	cli.StringOnce(cmd.Flags(), &scratchDir, "scratch-dir", "directory holding sandbox.vhdx")
	// Required in both the --ref and --base forms; only the ref/base choice is conditional.
	cli.Required(cmd, "scratch-dir")
	cli.StringArray(cmd.Flags(), &parents, "parent", "parent layer directory, topmost first, repeatable")
	return cmd
}

func unmountCmd(e cli.Emit) *cobra.Command {
	var scratchDir string
	cmd := &cobra.Command{
		Use:   "unmount --scratch-dir <dir>",
		Short: "detach the storage filter and the scratch VHD. ELEVATED",
		Long:  `Detach the storage filter and the scratch VHD. ELEVATED.`,
		Args:  cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return unmount(scratchDir, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &scratchDir, "scratch-dir", "directory holding sandbox.vhdx")
	cli.Required(cmd, "scratch-dir")
	return cmd
}

func importCmd(e cli.Emit) *cobra.Command {
	var src, layer string
	var parents []string
	cmd := &cobra.Command{
		Use:   "import --source <dir> --layer <dest-dir> [--parent <dir>]...",
		Short: "HcsImportLayer, folder to folder. ELEVATED",
		Long: `HcsImportLayer. Not working: fails path-not-found after writing Files.
ELEVATED.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := requireDir("--source", src); err != nil {
				return err
			}
			if err := checkParents(parents); err != nil {
				return err
			}
			return importLayer(src, layer, parents, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &src, "source", "source layer directory")
	cli.StringOnce(cmd.Flags(), &layer, "layer", "destination layer directory")
	cli.Required(cmd, "source", "layer")
	cli.StringArray(cmd.Flags(), &parents, "parent", "parent layer directory, topmost first, repeatable")
	return cmd
}

func exportCmd(e cli.Emit) *cobra.Command {
	var layer, dest string
	var parents []string
	var writable bool
	cmd := &cobra.Command{
		Use:   "export --layer <volume> --dest <existing-dir> [--parent <dir>]... [--writable]",
		Short: "HcsExportLayer from a mounted writable layer's volume",
		Long: `HcsExportLayer. Works on a *mounted* writable layer's volume path with
--writable, producing Files/Hives/tombstones. A legacy (wclayer) directory
layer fails partway; the legacy variants are not public hcsshim.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := requireDir("--layer", layer); err != nil {
				return err
			}
			// The destination must exist (API contract). HcsExportLayer's own error for a
			// missing destination does not name the path.
			if err := requireDir("--dest", dest); err != nil {
				return err
			}
			if err := checkParents(parents); err != nil {
				return err
			}
			return exportLayer(layer, dest, parents, writable, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &layer, "layer", "layer to export: a mounted writable layer's volume path")
	cli.StringOnce(cmd.Flags(), &dest, "dest", "existing destination directory")
	cli.Required(cmd, "layer", "dest")
	cli.StringArray(cmd.Flags(), &parents, "parent", "parent layer directory, topmost first, repeatable")
	cmd.Flags().BoolVar(&writable, "writable", false, "export as a writable layer")
	return cmd
}

func destroyCmd(e cli.Emit) *cobra.Command {
	var layer string
	cmd := &cobra.Command{
		Use:   "destroy --layer <dir>",
		Short: "HcsDestroyLayer, verified by directory absence. ELEVATED",
		Long: `HcsDestroyLayer, verified by directory absence. Layer directories defeat
ordinary deletion (restored security descriptors); this is the tool that
removes them. ELEVATED.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := requireDir("--layer", layer); err != nil {
				return err
			}
			return destroy(layer, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &layer, "layer", "layer directory to destroy")
	cli.Required(cmd, "layer")
	return cmd
}

// layerDataFor builds the LayerData every computestorage call wants: parents topmost first,
// absolute paths, schema 2.1. An empty parent list is a base layer.
func layerDataFor(parents []string) (computestorage.LayerData, error) {
	data := computestorage.LayerData{SchemaVersion: computestorage.Version{Major: 2, Minor: 1}}
	for _, p := range parents {
		g, err := hcsshim.NameToGuid(filepath.Base(p))
		if err != nil {
			return data, fmt.Errorf("NameToGuid(%s): %w", filepath.Base(p), err)
		}
		data.Layers = append(data.Layers, computestorage.Layer{Id: g.ToString(), Path: p, PathType: "AbsolutePath"})
	}
	return data, nil
}

func checkParents(parents []string) error {
	for _, p := range parents {
		if _, err := os.Stat(p); err != nil {
			return cli.Usagef("--parent %s: %v", p, err)
		}
	}
	return nil
}

// importLayer wraps HcsImportLayer: folder to folder, not a tar.
func importLayer(src, dest string, parents []string, e cli.Emit) error {
	data, err := layerDataFor(parents)
	if err != nil {
		return err
	}

	// Unlike ociwclayer, the raw computestorage syscalls do not enable privileges, and an
	// elevated token holds SeBackup/SeRestore disabled.
	err = winio.RunWithPrivileges([]string{winio.SeBackupPrivilege, winio.SeRestorePrivilege}, func() error {
		return computestorage.ImportLayer(context.Background(), dest, src, data)
	})
	if err != nil {
		return fmt.Errorf("ImportLayer: %w", err)
	}
	e.Result(map[string]any{
		"ok": true, "command": "storage import", "layer": dest, "source": src, "parents": parents,
	}, func() {
		fmt.Printf("imported %s\n  from: %s\n", dest, src)
	})
	return nil
}

func exportLayer(layer, dest string, parents []string, writable bool, e cli.Emit) error {
	data, err := layerDataFor(parents)
	if err != nil {
		return err
	}
	opts := computestorage.ExportLayerOptions{IsWritableLayer: writable}

	err = winio.RunWithPrivileges([]string{winio.SeBackupPrivilege, winio.SeRestorePrivilege}, func() error {
		return computestorage.ExportLayer(context.Background(), layer, dest, data, opts)
	})
	if err != nil {
		return fmt.Errorf("ExportLayer: %w", err)
	}
	e.Result(map[string]any{
		"ok": true, "command": "storage export", "layer": layer, "dest": dest,
		"parents": parents, "writable": opts.IsWritableLayer,
	}, func() {
		fmt.Printf("exported %s\n  to: %s\n", layer, dest)
	})
	return nil
}

// destroy wraps HcsDestroyLayer. Same caveat as wclayer's DestroyLayer: it can
// return success and leave the tree, so absence is verified rather than assumed.
func destroy(layer string, e cli.Emit) error {
	if err := computestorage.DestroyLayer(context.Background(), layer); err != nil {
		return fmt.Errorf("DestroyLayer: %w", err)
	}
	if _, err := os.Stat(layer); err == nil {
		return fmt.Errorf("DestroyLayer returned success but %s still exists", layer)
	}
	e.Result(map[string]any{
		"ok": true, "command": "storage destroy", "layer": layer,
	}, func() {
		fmt.Printf("destroyed %s\n", layer)
	})
	return nil
}

const (
	blankBaseName = "blank-base.vhdx"
	blankName     = "blank.vhdx"
	sandboxName   = "sandbox.vhdx"
	defaultSizeGB = 10
)

// requireDir is the shared argument shape: a named option that must be an existing directory.
// A \\?\Volume{...} path is a directory for every purpose here, but stat wants the trailing
// separator that callers conventionally omit.
func requireDir(name, v string) error {
	if err := cli.Require(name, v); err != nil {
		return err
	}
	probe := v
	if strings.HasPrefix(v, `\\?\Volume{`) && !strings.HasSuffix(v, `\`) {
		probe = v + `\`
	}
	fi, err := os.Stat(probe)
	if err != nil {
		return cli.Usagef("%s %s: %v", name, v, err)
	}
	if !fi.IsDir() {
		return cli.Usagef("%s %s is not a directory", name, v)
	}
	return nil
}

func setupBase(layer string, size uint64, e cli.Emit) error {
	base := filepath.Join(layer, blankBaseName)
	diff := filepath.Join(layer, blankName)
	e.Progress("SetupContainerBaseLayer: %s (%d GB) -- regenerates Hives/ and Layout in the layer", layer, size)
	if err := computestorage.SetupContainerBaseLayer(context.Background(), layer, base, diff, size); err != nil {
		return fmt.Errorf("SetupContainerBaseLayer: %w", err)
	}

	e.Result(map[string]any{
		"ok": true, "command": "storage setup-base", "layer": layer,
		"baseVhd": base, "diffVhd": diff, "sizeGB": size,
	}, func() {
		fmt.Printf("base ready\n  blank-base: %s\n  blank:      %s\n", base, diff)
	})
	return nil
}

// openScratch opens sandbox.vhdx in dir. AccessNone + no flags is what both attach and
// mount-path retrieval want on V2 VHDX.
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

// chainFor resolves a store reference to its materialized layer directories, topmost first,
// the order LayerData wants. The call site checks blank.vhdx in the base.
func chainFor(st *store.Store, ref string) ([]string, error) {
	rec, err := st.ReadRecord(ref)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, cli.Usagef("no record for %s -- pull and import it first", ref)
		}
		return nil, err
	}
	// ReadRecord guarantees structural soundness (non-empty, matched arrays, digest syntax).
	var chain []string // topmost first
	for _, d := range rec.DiffIDs {
		p := st.LayerPath(d)
		if _, err := os.Stat(p); err != nil {
			return nil, cli.Usagef("layer %s is not materialized -- run image import", filepath.Base(p))
		}
		chain = append([]string{p}, chain...)
	}
	return chain, nil
}

func mount(ref, base, storeDir, scratchDir string, parents []string, e cli.Emit) error {
	if ref != "" {
		// wclayer import creates blank.vhdx in base layers, so a store layer mounts as-is;
		// nothing here mutates the store.
		st, err := store.New(storeDir)
		if err != nil {
			return err
		}
		chain, err := chainFor(st, ref)
		if err != nil {
			return err
		}
		base = chain[len(chain)-1]
		parents = chain
	} else if len(parents) == 0 {
		parents = []string{base}
	}
	blank := filepath.Join(base, blankName)
	if _, err := os.Stat(blank); err != nil {
		return cli.Usagef("%s has no %s -- run storage setup-base first", base, blankName)
	}

	data, err := layerDataFor(parents)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		return err
	}
	sandbox := filepath.Join(scratchDir, sandboxName)
	fresh := false
	if _, err := os.Stat(sandbox); err != nil {
		if err := copyFile(blank, sandbox); err != nil {
			return fmt.Errorf("copy %s -> %s: %w", blank, sandbox, err)
		}
		fresh = true
		e.Progress("scratch:   %s (fresh from %s)", sandbox, blankName)
	} else {
		e.Progress("scratch:   %s (existing, not reinitialized)", sandbox)
	}

	h, err := vhd.OpenVirtualDisk(sandbox, vhd.VirtualDiskAccessNone, vhd.OpenVirtualDiskFlagNone)
	if err != nil {
		return fmt.Errorf("OpenVirtualDisk(%s): %w", sandbox, err)
	}
	defer syscall.CloseHandle(h)

	// PermanentLifetime: the mount must outlive this process. Without it the volume vanishes
	// when the handle closes.
	ctx := context.Background()
	if err := vhd.AttachVirtualDisk(h, vhd.AttachVirtualDiskFlagPermanentLifetime,
		&vhd.AttachVirtualDiskParameters{Version: 2}); err != nil {
		return fmt.Errorf("AttachVirtualDisk: %w", err)
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
		return fmt.Errorf("GetLayerVhdMountPath: %w", err)
	}
	e.Progress("volume:    %s", vol)

	if fresh {
		if err := computestorage.InitializeWritableLayer(ctx, vol, data); err != nil {
			undo()
			return fmt.Errorf("InitializeWritableLayer: %w", err)
		}
		e.Progress("InitializeWritableLayer ok")
	}
	if err := computestorage.AttachLayerStorageFilter(ctx, vol, data); err != nil {
		undo()
		return fmt.Errorf("AttachLayerStorageFilter: %w", err)
	}

	e.Result(map[string]any{
		"ok": true, "command": "storage mount", "scratch": sandbox,
		"volume": vol, "parents": parents, "fresh": fresh,
	}, func() {
		fmt.Printf("mounted\n  scratch: %s\n  volume:  %s\n", sandbox, vol)
	})
	return nil
}

func unmount(dir string, e cli.Emit) error {
	h, sandbox, err := openScratch(dir)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	ctx := context.Background()

	// Both steps are attempted regardless of earlier failures: a half-unmounted scratch
	// should lose as much as possible.
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
		return first
	}

	e.Result(map[string]any{
		"ok": true, "command": "storage unmount", "scratch": sandbox,
	}, func() {
		fmt.Printf("unmounted %s\n", sandbox)
	})
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
