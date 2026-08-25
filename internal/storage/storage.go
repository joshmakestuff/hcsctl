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
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/go-winio/vhd"
	"github.com/Microsoft/hcsshim/computestorage"
	"github.com/Microsoft/hcsshim/osversion"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/layerid"
	"github.com/joshmakestuff/hcsctl/internal/scratch"
	"github.com/joshmakestuff/hcsctl/internal/store"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

// Command is `hcsctl storage`.
func Command(e cli.Emit) *cobra.Command {
	return cli.Group("storage", "VHD-backed layers via computestorage",
		setupBaseCmd(e), setupVolumeCmd(e), mountCmd(e), unmountCmd(e), importCmd(e), exportCmd(e),
		destroyCmd(e), attachOverlayCmd(e), detachOverlayCmd(e))
}

func setupBaseCmd(e cli.Emit) *cobra.Command {
	var layer, sizeGB string
	var uvm bool
	cmd := &cobra.Command{
		Use:   "setup-base --layer <dir> [--uvm] [--size-gb N]",
		Short: "prepare a base layer for VHD-backed use. MUTATES the layer, ELEVATED",
		Long: `Prepare a base layer for VHD-backed (computestorage) use: blank-base.vhdx and
blank.vhdx created inside the layer directory. MUTATES the layer -- Hives/ and
Layout are regenerated -- so point it at a copy, not a store layer.

--uvm prepares the layer's utility VM instead: SystemTemplateBase.vhdx and
SystemTemplate.vhdx under UtilityVM\, from UtilityVM\Files. The UVM base VHD
is created but not formatted -- SetupBaseOSLayer writes the boot filesystem --
so a container base and a utility VM base are separate preparations of the
same layer. ELEVATED.`,
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
			// Both calls mutate their input (SetupBaseOSLayer regenerates Hives/ and
			// Layout); the shape check runs before the mutation.
			if uvm {
				// The call takes the UtilityVM directory, but Files under it is what
				// proves the layer actually carries a utility VM.
				if _, err := os.Stat(filepath.Join(layer, uvmFilesPath)); err != nil {
					return cli.Usagef(`--layer %s has no %s -- the image carries no utility VM`, layer, uvmFilesPath)
				}
				return setupUVMBase(layer, size, e)
			}
			if _, err := os.Stat(filepath.Join(layer, "Files")); err != nil {
				return cli.Usagef("--layer %s has no Files directory -- not a materialized layer", layer)
			}
			return setupBase(layer, size, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &layer, "layer", "layer directory to prepare")
	cli.Required(cmd, "layer")
	cli.StringOnce(cmd.Flags(), &sizeGB, "size-gb", "base VHD size in GB (default 10)")
	cmd.Flags().BoolVar(&uvm, "uvm", false, "prepare the layer's utility VM base instead of the container base")
	return cmd
}

func setupVolumeCmd(e cli.Emit) *cobra.Command {
	var layer, volume, layerType string
	cmd := &cobra.Command{
		Use:   "setup-volume --layer <dir> --volume <volume> [--type container|vm]",
		Short: "HcsSetupBaseOSVolume: write the base OS onto a mounted volume. ELEVATED",
		Long: `HcsSetupBaseOSVolume -- the volume-taking variant of the base OS setup that
setup-base performs against a VHD handle.

Two measured requirements, neither of which the API reports as an error:

The volume must be a writable-layer-formatted volume (what storage mount
attaches). On a plain NTFS volume the call returns SUCCESS and does nothing at
all, so this verb verifies the WcSandboxState marker afterwards and fails if
the call was a no-op.

The layer must NOT already carry Hives\ or layout: either one alone makes the
call fail "file already exists", so this runs on a layer that has been through
neither wclayer import nor a previous base setup -- and the call regenerates
both, so a layer is single-use here.

Build 19645 or newer. MUTATES both the layer and the volume. ELEVATED.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			opts, err := osLayerOptions(layerType)
			if err != nil {
				return err
			}
			if err := requireDir("--layer", layer); err != nil {
				return err
			}
			if err := requireDir("--volume", volume); err != nil {
				return err
			}
			if b := osversion.Build(); b < 19645 {
				return cli.Usagef("SetupBaseOSVolume needs build 19645 or newer, host is %d", b)
			}
			// Measured: either artifact alone makes the call fail "file already exists",
			// which names neither the layer nor the artifact.
			for _, a := range []string{"Hives", "layout"} {
				if _, err := os.Stat(filepath.Join(layer, a)); err == nil {
					return cli.Usagef("--layer %s already carries %s -- SetupBaseOSVolume needs a layer that has been through neither wclayer import nor a previous base setup", layer, a)
				}
			}
			e.Progress("SetupBaseOSVolume: %s -> %s (%s) -- regenerates Hives/ and Layout in the layer", layer, volume, opts.Type)
			if err := computestorage.SetupBaseOSVolume(context.Background(), layer, volume, opts); err != nil {
				return fmt.Errorf("SetupBaseOSVolume: %w", err)
			}
			// Measured: on a volume that is not writable-layer-formatted the call returns
			// success and writes nothing, so the nil return proves nothing on its own.
			// WcSandboxState is what the handle variant leaves behind.
			if _, err := os.Stat(volumeJoin(volume, "WcSandboxState")); err != nil {
				return fmt.Errorf("SetupBaseOSVolume returned success but wrote nothing to %s -- the volume is not writable-layer-formatted (use the volume from storage mount)", volume)
			}
			e.Result(map[string]any{
				"ok": true, "command": "storage setup-volume", "layer": layer,
				"volume": volume, "type": string(opts.Type),
			}, func() {
				fmt.Printf("base OS written\n  layer:  %s\n  volume: %s\n", layer, volume)
			})
			return nil
		},
	}
	cli.StringOnce(cmd.Flags(), &layer, "layer", "layer directory carrying the base OS files")
	cli.StringOnce(cmd.Flags(), &volume, "volume", "mounted, formatted volume to write onto")
	cli.Required(cmd, "layer", "volume")
	cli.StringOnce(cmd.Flags(), &layerType, "type", "container (default) or vm")
	return cmd
}

func osLayerOptions(layerType string) (computestorage.OsLayerOptions, error) {
	switch strings.ToLower(layerType) {
	case "", "container":
		return computestorage.OsLayerOptions{Type: computestorage.OsLayerTypeContainer}, nil
	case "vm":
		return computestorage.OsLayerOptions{Type: computestorage.OsLayerTypeVM}, nil
	default:
		return computestorage.OsLayerOptions{}, cli.Usagef("--type must be container or vm, got %q", layerType)
	}
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
		Long: `HcsImportLayer. Destination is a plain directory; the source must be a
complete export (Files, Hives, tombstones.txt) -- a partial or wrapped export
fails path-not-found after writing Files. ELEVATED.`,
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

func attachOverlayCmd(e cli.Emit) *cobra.Command {
	var volume, filterType string
	var layers []string
	cmd := &cobra.Command{
		Use:   "attach-overlay --volume <writable-volume> --layer <path>... [--filter-type unionfs|wcifs]",
		Short: "HcsAttachOverlayFilter: overlay read-only layers onto a writable volume. ELEVATED",
		Long: `HcsAttachOverlayFilter. Overlays read-only layer content onto a writable
volume: the volume then presents the union, with writes landing in the volume.
Layers topmost first. A layer under a mounted CIM volume is given by its path
inside that volume (hcsshim's convention puts container content under Files, so
that is usually <cim-volume>\Files); the layer id derives from the volume GUID,
or from the directory name for a plain path. unionfs is what hcsshim uses for
CIM layers; wcifs is the legacy directory-layer filter.

The writable volume must carry a WcSandboxState directory or the attach fails
with a bare path-not-found (measured) -- volumes prepared by setup-base or
InitializeWritableLayer have one; on a fresh volume, create it. ELEVATED.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			data, err := overlayLayerData(filterType, layers)
			if err != nil {
				return err
			}
			if err := requireDir("--volume", volume); err != nil {
				return err
			}
			for _, l := range layers {
				if err := requireDir("--layer", l); err != nil {
					return err
				}
			}
			// Without this the filter fails with a bare path-not-found (measured on
			// 26200 and 29641); the check turns it into an error naming the fix.
			if _, err := os.Stat(volumeJoin(volume, "WcSandboxState")); err != nil {
				return cli.Usagef("--volume %s has no WcSandboxState directory -- the overlay filter requires one (create it, or use a volume prepared by setup-base or InitializeWritableLayer)", volume)
			}
			if err := computestorage.AttachOverlayFilter(context.Background(), volume, data); err != nil {
				return fmt.Errorf("AttachOverlayFilter: %w", err)
			}
			e.Result(map[string]any{
				"ok": true, "command": "storage attach-overlay", "volume": volume,
				"filterType": string(data.FilterType), "layers": data.Layers,
			}, func() {
				fmt.Printf("overlay attached (%s)\n  volume: %s\n", data.FilterType, volume)
			})
			return nil
		},
	}
	cli.StringOnce(cmd.Flags(), &volume, "volume", "writable volume to overlay onto")
	cli.Required(cmd, "volume")
	cli.StringArray(cmd.Flags(), &layers, "layer", "read-only layer path, topmost first, repeatable")
	cli.StringOnce(cmd.Flags(), &filterType, "filter-type", "unionfs or wcifs (default unionfs)")
	return cmd
}

func detachOverlayCmd(e cli.Emit) *cobra.Command {
	var volume, filterType string
	cmd := &cobra.Command{
		Use:   "detach-overlay --volume <writable-volume> [--filter-type unionfs|wcifs]",
		Short: "HcsDetachOverlayFilter. ELEVATED",
		Long: `HcsDetachOverlayFilter: remove the overlay from a writable volume. The
filter type must match the one attached. ELEVATED.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			ft, err := normalizeFilterType(filterType)
			if err != nil {
				return err
			}
			if err := requireDir("--volume", volume); err != nil {
				return err
			}
			// FileSystemFilterType is a named string type in an hcsshim-internal package;
			// only an untyped constant converts to it without the import, hence the switch.
			switch ft {
			case "unionfs":
				err = computestorage.DetachOverlayFilter(context.Background(), volume, "UnionFS")
			case "wcifs":
				err = computestorage.DetachOverlayFilter(context.Background(), volume, "WCIFS")
			}
			if err != nil {
				return fmt.Errorf("DetachOverlayFilter: %w", err)
			}
			e.Result(map[string]any{
				"ok": true, "command": "storage detach-overlay", "volume": volume, "filterType": filterName(ft),
			}, func() {
				fmt.Printf("overlay detached\n  volume: %s\n", volume)
			})
			return nil
		},
	}
	cli.StringOnce(cmd.Flags(), &volume, "volume", "writable volume carrying the overlay")
	cli.Required(cmd, "volume")
	cli.StringOnce(cmd.Flags(), &filterType, "filter-type", "unionfs or wcifs (default unionfs)")
	return cmd
}

func normalizeFilterType(s string) (string, error) {
	switch strings.ToLower(s) {
	case "", "unionfs":
		return "unionfs", nil
	case "wcifs":
		return "wcifs", nil
	default:
		return "", cli.Usagef("--filter-type must be unionfs or wcifs, got %q", s)
	}
}

func filterName(normalized string) string {
	if normalized == "wcifs" {
		return "WCIFS"
	}
	return "UnionFS"
}

// overlayLayerData builds the LayerData AttachOverlayFilter wants: FilterType plus layers
// topmost first, no schema version (matching hcsshim's own overlay attach). A layer id is
// the mount GUID when the path sits under a \\?\Volume{...} mount, else NameToGuid of the
// directory name, the same derivation layerDataFor uses.
func overlayLayerData(filterType string, layers []string) (computestorage.LayerData, error) {
	var data computestorage.LayerData
	ft, err := normalizeFilterType(filterType)
	if err != nil {
		return data, err
	}
	if ft == "wcifs" {
		data.FilterType = "WCIFS"
	} else {
		data.FilterType = "UnionFS"
	}
	if len(layers) == 0 {
		return data, cli.Usagef("--layer is required")
	}
	for _, l := range layers {
		id, err := overlayLayerID(l)
		if err != nil {
			return data, err
		}
		data.Layers = append(data.Layers, computestorage.Layer{Id: id, Path: l})
	}
	return data, nil
}

// volumeJoin appends a name under a volume or directory path without filepath.Join's
// cleaning, which mangles the \\?\ prefix.
func volumeJoin(vol, name string) string {
	if !strings.HasSuffix(vol, `\`) {
		vol += `\`
	}
	return vol + name
}

func overlayLayerID(p string) (string, error) {
	const volPrefix = `\\?\Volume{`
	if strings.HasPrefix(p, volPrefix) {
		i := strings.Index(p, "}")
		if i < 0 {
			return "", cli.Usagef(`--layer %s is not a \\?\Volume{guid} path`, p)
		}
		g, err := guid.FromString(p[len(volPrefix):i])
		if err != nil {
			return "", cli.Usagef("--layer %s: %v", p, err)
		}
		return g.String(), nil
	}
	return layerid.For(filepath.Base(p)), nil
}

// layerDataFor builds the LayerData every computestorage call wants: parents topmost first,
// absolute paths, schema 2.1. An empty parent list is a base layer.
func layerDataFor(parents []string) (computestorage.LayerData, error) {
	return layerid.DataFor(parents)
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

	// The utility VM layout, matching hcsshim's own names for these files.
	uvmPath        = `UtilityVM`
	uvmFilesPath   = `UtilityVM\Files`
	uvmBaseVhd     = "SystemTemplateBase.vhdx"
	uvmTemplateVhd = "SystemTemplate.vhdx"
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

// setupUVMBase wraps SetupUtilityVMBaseLayer: the utility VM half of base preparation.
// Unlike the container base, the VHD is created but not formatted -- SetupBaseOSLayer
// writes the boot filesystem into it.
//
// uvmPath is the layer's UtilityVM directory, NOT UtilityVM\Files: hcsshim documents it
// as "the path to the UtilityVM filesystem", but the Files path fails ERROR_GEN_FAILURE
// and the directory above it succeeds (measured).
func setupUVMBase(layer string, size uint64, e cli.Emit) error {
	uvm := filepath.Join(layer, uvmPath)
	base := filepath.Join(layer, uvmPath, uvmBaseVhd)
	tmpl := filepath.Join(layer, uvmPath, uvmTemplateVhd)
	e.Progress("SetupUtilityVMBaseLayer: %s (%d GB) -- regenerates Hives/ and Layout in the UVM", uvm, size)
	if err := computestorage.SetupUtilityVMBaseLayer(context.Background(), uvm, base, tmpl, size); err != nil {
		return fmt.Errorf("SetupUtilityVMBaseLayer: %w", err)
	}
	// The helper removes and recreates both VHDs, so their presence is the postcondition.
	for _, p := range []string{base, tmpl} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("SetupUtilityVMBaseLayer returned success but %s is missing: %w", p, err)
		}
	}
	e.Result(map[string]any{
		"ok": true, "command": "storage setup-base", "layer": layer, "uvm": true,
		"uvmPath": uvm, "baseVhd": base, "templateVhd": tmpl, "sizeGB": size,
	}, func() {
		fmt.Printf("utility VM base ready\n  base:     %s\n  template: %s\n", base, tmpl)
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

// chainFor resolves a store reference via the one chain resolver.
func chainFor(st *store.Store, ref string) ([]string, error) {
	rec, err := st.ReadRecord(ref)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, cli.Usagef("no record for %s -- pull and import it first", ref)
		}
		return nil, err
	}
	chain, err := st.Chain(rec)
	if err != nil {
		return nil, cli.Usagef("%v", err)
	}
	return chain, nil
}

func mount(ref, base, storeDir, scratchDir string, parents []string, e cli.Emit) error {
	if ref != "" {
		// image import completes base layers with blank.vhdx, so a store layer
		// mounts as-is; nothing here mutates the store.
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

	// Same ACE prep as PrepareScratchVHD: a xenon consuming this scratch opens
	// the VHD under the Virtual Machines group at create.
	if err := scratch.GrantVMGroupAccess(sandbox); err != nil {
		return err
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
