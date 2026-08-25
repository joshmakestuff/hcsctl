//go:build windows

package image

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	winio "github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/computestorage"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/layerid"
	"github.com/joshmakestuff/hcsctl/internal/scratch"
	"github.com/joshmakestuff/hcsctl/internal/store"
	"github.com/joshmakestuff/hcsctl/internal/transport"
)

// The modern import pipeline, per layer bottom-up (measured end to end,
// hcsspike modernlc, docs/findings.md 2026-08-25):
//
//	blob -> transport.Stage (plain files, no privileges)
//	     -> HcsImportLayer under SeBackup/SeRestore, parents topmost-first
//	     -> rename-publish into <root>/layers/<diffID>
//	base only, afterward:
//	     -> SetupContainerBaseLayer (creates blank-base.vhdx + blank.vhdx,
//	        replaces the imported Hives with *_BASE hardlinks)
//	     -> re-add the five *_Delta stubs (setup strips them; HcsExportLayer
//	        of the base later requires them)
//	     -> UtilityVM present: SetupUtilityVMBaseLayer + the Virtual Machines
//	        group ACE on both template VHDs (the xenon requirement)
//
// No wclayer anywhere: zero-parent HcsImportLayer runs no base processing, and
// setup-base IS the modern completion of the base.

type importResult struct {
	OK      bool     `json:"ok"`
	Command string   `json:"command"`
	Ref     string   `json:"ref"`
	Chain   []string `json:"layerChain"` // topmost first, the shape a consumer needs
	Bytes   int64    `json:"bytes"`
}

func importImage(ref, storeDir string, sizeGB uint64, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	rec, err := st.ReadRecord(ref)
	if err != nil {
		if os.IsNotExist(err) {
			return cli.Usagef("no record for %s in %s -- pull it first", ref, st.Root)
		}
		return err
	}
	if err := st.CheckFormat(); err != nil {
		return err
	}

	tmpRoot := filepath.Join(st.Root, "tmp")
	if err := os.MkdirAll(tmpRoot, 0o755); err != nil {
		return err
	}
	sweepOrphans(tmpRoot, e)

	ctx := context.Background()
	var chain []string // topmost first
	var total int64

	for i, diffID := range rec.DiffIDs {
		entry := st.LayerPath(diffID)
		if _, err := os.Stat(filepath.Join(entry, "Files")); err == nil {
			e.Progress("  layer %d/%d already materialized: %s", i+1, len(rec.DiffIDs), entry)
			// A crash between publish and base completion leaves Files without
			// blank.vhdx; finish the base now.
			if i == 0 {
				if _, err := os.Stat(filepath.Join(entry, "blank.vhdx")); err != nil {
					if err := finishBase(ctx, entry, sizeGB, e); err != nil {
						return err
					}
				}
			}
			chain = append([]string{entry}, chain...)
			continue
		}

		blob := st.BlobPath(trimSha(rec.LayerDigests[i]))
		f, err := os.Open(blob)
		if err != nil {
			return fmt.Errorf("open blob for layer %d: %w", i, err)
		}

		// Stage the transport form. Plain files -- no privileges; parents are
		// consulted only to materialize cross-layer hardlinks.
		staging := filepath.Join(tmpRoot, "stage-"+randSuffix())
		e.Progress("  layer %d/%d staging -> %s", i+1, len(rec.DiffIDs), staging)
		start := time.Now()
		stats, err := transport.Stage(f, staging, chain)
		f.Close()
		if err != nil {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("stage layer %d: %w", i, err)
		}
		e.Progress("     staged %d files, %d dirs, %d links, %d tombstones in %s",
			stats.Files, stats.Dirs, stats.Links, stats.Tombstones, time.Since(start).Round(time.Millisecond))

		// Import into a temp sibling and publish by rename, so a layer at its
		// final path is always complete.
		importTmp := filepath.Join(tmpRoot, "import-"+randSuffix())
		data, err := layerid.DataFor(chain)
		if err != nil {
			_ = os.RemoveAll(staging)
			return err
		}
		if err := os.MkdirAll(importTmp, 0o755); err != nil {
			_ = os.RemoveAll(staging)
			return err
		}
		e.Progress("  layer %d/%d HcsImportLayer (%d parents)", i+1, len(rec.DiffIDs), len(chain))
		start = time.Now()
		err = winio.RunWithPrivileges([]string{winio.SeBackupPrivilege, winio.SeRestorePrivilege}, func() error {
			return computestorage.ImportLayer(ctx, importTmp, staging, data)
		})
		_ = os.RemoveAll(staging)
		if err != nil {
			_ = computestorage.DestroyLayer(ctx, importTmp)
			return fmt.Errorf("import layer %d (rerun elevated?): %w", i, err)
		}
		e.Progress("     imported in %s", time.Since(start).Round(time.Millisecond))
		total += stats.Bytes

		if err := os.MkdirAll(filepath.Dir(entry), 0o755); err != nil {
			_ = computestorage.DestroyLayer(ctx, importTmp)
			return err
		}
		if err := os.Rename(importTmp, entry); err != nil {
			_ = computestorage.DestroyLayer(ctx, importTmp)
			return fmt.Errorf("publish layer %d: %w", i, err)
		}

		// Base completion happens AFTER publish: SetupContainerBaseLayer bakes
		// blank-base.vhdx's ABSOLUTE path into blank.vhdx's parent locator
		// (measured -- a rename after setup breaks the VHDX chain), so the
		// VHDs must be created at the layer's final path. blank.vhdx is the
		// completion sentinel store.Chain checks, and the skip branch above
		// heals a crash between publish and completion.
		if i == 0 {
			if err := finishBase(ctx, entry, sizeGB, e); err != nil {
				return err
			}
		}
		chain = append([]string{entry}, chain...)
	}

	if err := st.WriteFormat(); err != nil {
		return err
	}

	res := importResult{OK: true, Command: "image import", Ref: rec.Ref, Chain: chain, Bytes: total}
	e.Result(res, func() {
		fmt.Println("layer chain (topmost first):")
		for _, p := range chain {
			fmt.Printf("  %s\n", p)
		}
	})
	return nil
}

// finishBase completes a freshly imported base layer: container base setup,
// the delta-hive stubs setup strips, and -- when the image carries a utility
// VM -- the UVM template VHDs with the Virtual Machines group ACE.
func finishBase(ctx context.Context, base string, sizeGB uint64, e cli.Emit) error {
	e.Progress("  SetupContainerBaseLayer (%d GB)", sizeGB)
	start := time.Now()
	if err := computestorage.SetupContainerBaseLayer(ctx, base,
		filepath.Join(base, "blank-base.vhdx"), filepath.Join(base, "blank.vhdx"), sizeGB); err != nil {
		return fmt.Errorf("SetupContainerBaseLayer: %w", err)
	}
	e.Progress("     done in %s", time.Since(start).Round(time.Millisecond))

	// Setup replaces the imported Hives with *_BASE hardlinks and strips the
	// *_Delta stubs; HcsExportLayer of this base later requires them back
	// (measured), so they are part of the finished shape.
	if err := transport.WriteDeltaHiveStubs(filepath.Join(base, "Hives")); err != nil {
		return err
	}

	uvm := filepath.Join(base, "UtilityVM")
	if _, err := os.Stat(filepath.Join(uvm, "Files")); err != nil {
		return nil // no utility VM in this image
	}
	e.Progress("  SetupUtilityVMBaseLayer (%d GB)", sizeGB)
	start = time.Now()
	// The UVM directory, NOT UtilityVM\Files -- the Files path fails
	// ERROR_GEN_FAILURE (measured).
	if err := computestorage.SetupUtilityVMBaseLayer(ctx, uvm,
		filepath.Join(uvm, "SystemTemplateBase.vhdx"), filepath.Join(uvm, "SystemTemplate.vhdx"), sizeGB); err != nil {
		return fmt.Errorf("SetupUtilityVMBaseLayer: %w", err)
	}
	e.Progress("     done in %s", time.Since(start).Round(time.Millisecond))
	// A xenon's worker opens the template VHDs under the Virtual Machines
	// group; grant at import so xenon create stays read-only against the store.
	for _, vhd := range []string{
		filepath.Join(uvm, "SystemTemplateBase.vhdx"),
		filepath.Join(uvm, "SystemTemplate.vhdx"),
	} {
		if err := scratch.GrantVMGroupAccess(vhd); err != nil {
			return err
		}
	}
	return nil
}

// sweepOrphans clears leftovers of interrupted imports. Staging dirs are plain
// files; import dirs may need DestroyLayer.
func sweepOrphans(tmpRoot string, e cli.Emit) {
	entries, err := os.ReadDir(tmpRoot)
	if err != nil {
		return
	}
	for _, ent := range entries {
		p := filepath.Join(tmpRoot, ent.Name())
		if err := os.RemoveAll(p); err != nil {
			if derr := computestorage.DestroyLayer(context.Background(), p); derr != nil {
				e.Progress("WARNING: orphaned import temp %s: %v", p, derr)
			}
		}
	}
}

func randSuffix() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func trimSha(d string) string {
	if len(d) > 7 && d[:7] == "sha256:" {
		return d[7:]
	}
	return d
}
