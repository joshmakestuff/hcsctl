//go:build windows

package image

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	winio "github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/pkg/ociwclayer"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/store"
)

type importResult struct {
	OK      bool     `json:"ok"`
	Command string   `json:"command"`
	Ref     string   `json:"ref"`
	Chain   []string `json:"layerChain"` // topmost first, the shape a consumer needs
	Bytes   int64    `json:"bytes"`
}

func importImage(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--ref", "--store"); err != nil {
		return cli.Usage, err
	}
	ref, err := a.Require("--ref")
	if err != nil {
		return cli.Usage, err
	}
	st, err := store.New(a.Option("--store"))
	if err != nil {
		return cli.Failed, err
	}

	rec, err := st.ReadRecord(ref)
	if err != nil {
		if os.IsNotExist(err) {
			return cli.Usage, cli.Usagef("no record for %s in %s -- pull it first", ref, st.Root)
		}
		return cli.Failed, err
	}

	// hcsshim's ImportLayerFromTar documents that the caller must hold backup and restore
	// privileges. This can only ENABLE what the token already carries, so it is not a way
	// around elevation: import needs an enabled BUILTIN\Administrators SID at
	// ProcessBaseLayer, which is a group check no user-rights grant satisfies.
	if err := winio.EnableProcessPrivileges([]string{winio.SeBackupPrivilege, winio.SeRestorePrivilege}); err != nil {
		return cli.Failed, fmt.Errorf("enable backup/restore privileges (rerun elevated): %w", err)
	}
	e.Progress("privileges: SeBackupPrivilege + SeRestorePrivilege enabled")

	ctx := context.Background()
	var chain []string // topmost first
	var total int64

	for i, diffID := range rec.DiffIDs {
		entry := st.LayerPath(diffID)

		if _, err := os.Stat(filepath.Join(entry, "Files")); err == nil {
			e.Progress("  layer %d/%d already materialized: %s", i+1, len(rec.DiffIDs), entry)
			chain = append([]string{entry}, chain...)
			continue
		}

		blob := st.BlobPath(trimSha(rec.LayerDigests[i]))
		f, err := os.Open(blob)
		if err != nil {
			return cli.Failed, fmt.Errorf("open blob for layer %d: %w", i, err)
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return cli.Failed, fmt.Errorf("gunzip layer %d: %w", i, err)
		}

		e.Progress("  layer %d/%d -> %s", i+1, len(rec.DiffIDs), entry)
		start := time.Now()

		// Extract + ProcessBaseLayer + ProcessUtilityVMImage, in one call. parents are the
		// already-materialized layers below this one, TOPMOST FIRST -- hcsshim's doc says
		// "lowest to highest" but its own callers pass topmost-first, and the six-layer
		// dotnet/runtime import and mount in issue #2 settled it: topmost-first materializes
		// and mounts correctly.
		n, err := ociwclayer.ImportLayerFromTar(ctx, gz, entry, chain)
		gz.Close()
		f.Close()
		if err != nil {
			return cli.Failed, fmt.Errorf("import layer %d: %w", i, err)
		}
		e.Progress("     %d MB in %s", n/(1024*1024), time.Since(start).Round(time.Millisecond))
		total += n

		chain = append([]string{entry}, chain...)
	}

	// hcsshim does NOT write layerchain.json -- it is a moby convention, and the consumer of
	// this store reads it. A base layer's chain is JSON null; higher layers list their parents
	// topmost first.
	for i, entry := range chain {
		parents := chain[i+1:]
		if err := writeLayerChain(entry, parents); err != nil {
			return cli.Failed, fmt.Errorf("write layerchain.json: %w", err)
		}
	}

	res := importResult{OK: true, Command: "image import", Ref: rec.Ref, Chain: chain, Bytes: total}
	e.Result(res, func() {
		fmt.Println("layer chain (topmost first):")
		for _, p := range chain {
			fmt.Printf("  %s\n", p)
		}
	})
	return cli.OK, nil
}

func writeLayerChain(entry string, parents []string) error {
	var b []byte
	var err error
	if len(parents) == 0 {
		b = []byte("null")
	} else if b, err = json.Marshal(parents); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(entry, "layerchain.json"), b, 0o644)
}

func trimSha(d string) string {
	if len(d) > 7 && d[:7] == "sha256:" {
		return d[7:]
	}
	return d
}
