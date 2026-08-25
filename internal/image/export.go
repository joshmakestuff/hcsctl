//go:build windows

package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	winio "github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/computestorage"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/layerid"
	"github.com/joshmakestuff/hcsctl/internal/store"
	"github.com/joshmakestuff/hcsctl/internal/transport"
)

// Export route (measured, hcsspike modernlc exportdir cell, 2026-08-25):
// HcsExportLayer takes a COMMITTED layer directory as its source -- the diff
// layers with their parents, and the zero-parent base -- with no wclayer
// Activate/Prepare dance. The one requirement is Hives\*_Delta in the source,
// which import guarantees (it re-adds the stubs SetupContainerBaseLayer
// strips). The export product is the transport format; transport.WalkToTar
// turns it into the OCI layer tar, walked exactly the way hcsshim's own
// legacy reader walks it.

type exportResult struct {
	OK      bool             `json:"ok"`
	Command string           `json:"command"`
	Ref     string           `json:"ref"`
	Out     string           `json:"out"`
	Layers  []exportLayerDoc `json:"layers"`
}

type exportLayerDoc struct {
	Index  int    `json:"index"`
	DiffID string `json:"diffID"`
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	Sha256 string `json:"sha256"`
}

// tarName makes order and identity explicit in the filename: index, then the DiffID with the
// digest-algorithm separator flattened so the name is a single path segment.
func tarName(index int, diffID string) string {
	return fmt.Sprintf("%03d-%s.tar", index, strings.ReplaceAll(diffID, ":", "-"))
}

func exportImage(ref, out, storeDir string, e cli.Emit) error {
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

	absOut, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if _, err := os.Stat(absOut); err == nil {
		return cli.Usagef("output already exists: %s -- export never overwrites", absOut)
	}

	// The chain check doubles as the materialization gate.
	chainTopFirst, err := st.Chain(rec)
	if err != nil {
		return cli.Usagef("%v", err)
	}
	// Base-first, parallel to the record, for the per-layer loop.
	dirs := make([]string, len(chainTopFirst))
	for i := range chainTopFirst {
		dirs[i] = chainTopFirst[len(chainTopFirst)-1-i]
	}

	// SeBackup for the transport walk's OpenForBackup reads; both privileges
	// around HcsExportLayer -- the raw computestorage syscalls do not enable
	// them themselves, and an elevated token holds them disabled.
	if err := winio.EnableProcessPrivileges([]string{winio.SeBackupPrivilege, winio.SeRestorePrivilege}); err != nil {
		return fmt.Errorf("enable backup/restore privileges (rerun elevated): %w", err)
	}

	// Stage in a sibling of the destination so the final publish is one rename on the same
	// volume; a failure mid-export removes the staging dir and leaves no partial output.
	staging, err := os.MkdirTemp(filepath.Dir(absOut), filepath.Base(absOut)+".staging-")
	if err != nil {
		return fmt.Errorf("create staging next to %s: %w", absOut, err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(staging)
		}
	}()

	ctx := context.Background()
	layers := make([]exportLayerDoc, 0, len(dirs))
	for i, dir := range dirs {
		name := tarName(i, rec.DiffIDs[i])
		e.Progress("  layer %d/%d -> %s", i+1, len(dirs), name)
		start := time.Now()

		// Parents of layer i, topmost first: the layers below it.
		var parents []string
		for j := i - 1; j >= 0; j-- {
			parents = append(parents, dirs[j])
		}
		data, err := layerid.DataFor(parents)
		if err != nil {
			return err
		}
		transportDir, err := os.MkdirTemp(staging, fmt.Sprintf(".transport-%03d-", i))
		if err != nil {
			return err
		}
		if err := computestorage.ExportLayer(ctx, dir, transportDir, data, computestorage.ExportLayerOptions{}); err != nil {
			return fmt.Errorf("export layer %d/%d (%s): %w", i+1, len(dirs), rec.DiffIDs[i], err)
		}

		tarPath := filepath.Join(staging, name)
		f, err := os.Create(tarPath)
		if err != nil {
			return err
		}
		cw := &countHashWriter{w: f, h: sha256.New()}
		err = transport.WalkToTar(ctx, cw, transportDir)
		f.Close()
		_ = os.RemoveAll(transportDir)
		if err != nil {
			return fmt.Errorf("tar layer %d/%d (%s): %w", i+1, len(dirs), rec.DiffIDs[i], err)
		}

		e.Progress("     %d MB in %s", cw.n/(1024*1024), time.Since(start).Round(time.Millisecond))
		layers = append(layers, exportLayerDoc{
			Index:  i,
			DiffID: rec.DiffIDs[i],
			Path:   name,
			Bytes:  cw.n,
			Sha256: "sha256:" + hex.EncodeToString(cw.h.Sum(nil)),
		})
	}

	if err := os.Rename(staging, absOut); err != nil {
		return fmt.Errorf("publish %s -> %s: %w", staging, absOut, err)
	}
	published = true

	res := exportResult{OK: true, Command: "image export", Ref: rec.Ref, Out: absOut, Layers: layers}
	e.Result(res, func() {
		fmt.Printf("exported %d layer(s) of %s to %s\n", len(layers), rec.Ref, absOut)
		for _, l := range layers {
			fmt.Printf("  %s  %d MB\n", l.Path, l.Bytes/(1024*1024))
		}
	})
	return nil
}

// countHashWriter counts bytes and hashes what passes through, so the result document carries
// both without a second pass over multi-gigabyte tars.
type countHashWriter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (c *countHashWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	if n > 0 {
		c.h.Write(b[:n])
		c.n += int64(n)
	}
	return n, err
}
