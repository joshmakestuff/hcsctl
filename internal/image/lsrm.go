//go:build windows

package image

import (
	"fmt"
	"os"

	"github.com/Microsoft/hcsshim"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/store"
)

type lsEntry struct {
	Ref          string `json:"ref"`
	OSVersion    string `json:"osVersion"`
	Layers       int    `json:"layers"`
	Materialized bool   `json:"materialized"`
	PulledUTC    string `json:"pulledUtc"`
}

func list(storeDir string, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	recs, err := st.Records()
	if err != nil {
		return err
	}

	out := make([]lsEntry, 0, len(recs))
	for _, r := range recs {
		materialized := len(r.DiffIDs) > 0
		for _, d := range r.DiffIDs {
			if _, err := os.Stat(st.LayerPath(d)); err != nil {
				materialized = false
				break
			}
		}
		out = append(out, lsEntry{
			Ref: r.Ref, OSVersion: r.OSVersion, Layers: len(r.DiffIDs),
			Materialized: materialized, PulledUTC: r.PulledUTC,
		})
	}

	e.Result(map[string]any{"ok": true, "command": "image ls", "store": st.Root, "images": out}, func() {
		if len(out) == 0 {
			fmt.Printf("no images in %s\n", st.Root)
			return
		}
		fmt.Printf("%-52s %-18s %6s  %s\n", "REF", "OS VERSION", "LAYERS", "MATERIALIZED")
		for _, i := range out {
			fmt.Printf("%-52s %-18s %6d  %v\n", i.Ref, i.OSVersion, i.Layers, i.Materialized)
		}
	})
	return nil
}

func remove(ref, storeDir string, blobs bool, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	rec, err := st.ReadRecord(ref)
	if err != nil {
		if os.IsNotExist(err) {
			return cli.Usagef("no record for %s in %s", ref, st.Root)
		}
		return err
	}

	// A materialized layer carries restored security descriptors that ordinary file I/O cannot
	// delete. The layer driver removes them; that is what DestroyLayer is for, and it needs the
	// same elevation import did.
	removed := []string{}
	for _, d := range rec.DiffIDs {
		entry := st.LayerPath(d)
		if _, err := os.Stat(entry); err != nil {
			continue
		}
		if err := hcsshim.DestroyLayer(hcsshim.DriverInfo{}, entry); err != nil {
			return fmt.Errorf("destroy layer %s (rerun elevated?): %w", entry, err)
		}
		// The post-condition, not the return value: DestroyLayer can report success and leave
		// the tree behind.
		if _, err := os.Stat(entry); err == nil {
			return fmt.Errorf("layer still present after DestroyLayer: %s", entry)
		}
		removed = append(removed, entry)
		e.Progress("removed %s", entry)
	}

	if blobs {
		for _, d := range rec.LayerDigests {
			blob := st.BlobPath(trimSha(d))
			if err := os.Remove(blob); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove blob %s: %w", blob, err)
			}
			e.Progress("removed %s", blob)
		}
	}

	if err := st.RemoveRecord(ref); err != nil {
		return err
	}

	e.Result(map[string]any{
		"ok": true, "command": "image rm", "ref": rec.Ref, "layersRemoved": removed,
	}, func() {
		fmt.Printf("removed %d layer(s) and the record for %s\n", len(removed), rec.Ref)
	})
	return nil
}
