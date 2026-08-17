//go:build windows

// Package layer is the `hcsctl layer` verb group: it turns a materialized image chain into a
// mounted volume.
//
// An imported image is read-only layer directories. To see the merged filesystem, the chain
// needs a writable scratch layer on top, activated and prepared, before Windows returns a
// volume path. That is four calls in hcsshim's root package:
//
//	CreateScratchLayer(info, scratchPath, "", parents)  -- writable layer over the chain
//	ActivateLayer(info, scratchPath)                    -- attach it to the layer driver
//	PrepareLayer(info, scratchPath, parents)            -- stack the read-only layers under it
//	GetLayerMountPath(info, scratchPath)                -- the \\?\Volume{...} path
//
// DriverInfo is zero: layerPath() is filepath.Join(HomeDir, id), so an empty HomeDir means
// the id is the full path, which is how this store addresses layers.
//
// ELEVATED. PrepareLayer needs an enabled BUILTIN\Administrators SID (measured). It is a group
// check, not a privilege, so no user-rights grant substitutes.
package layer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Microsoft/hcsshim"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/store"
)

func Dispatch(a *cli.Args, e cli.Emit) (int, error) {
	switch a.Word(1) {
	case "mount":
		return mount(a, e)
	case "unmount":
		return unmount(a, e)
	case "ls":
		return list(a, e)
	case "":
		return cli.Usage, cli.Usagef("layer needs a subcommand: mount, unmount, ls")
	default:
		return cli.Usage, cli.Usagef("unknown layer subcommand %q (expected mount, unmount, ls)", a.Word(1))
	}
}

// scratchRoot holds one directory per mount, named by its id.
func scratchRoot(st *store.Store) string { return filepath.Join(st.Root, "scratch") }

func scratchPath(st *store.Store, id string) string { return filepath.Join(scratchRoot(st), id) }

// idFor turns a reference into a usable directory name so `--id` can be optional.
func idFor(ref string) string {
	return strings.NewReplacer("/", "_", ":", "_", "@", "_", "\\", "_").Replace(ref)
}

// resolveID is the only way mount and unmount obtain an id, and it validates the id. An
// unvalidated id reaches DestroyLayer on the elevated path (`--id ..` would name the store root).
func resolveID(a *cli.Args) (string, error) {
	id := a.Option("--id")
	if id == "" {
		if ref := a.Option("--ref"); ref != "" {
			id = idFor(ref)
		} else {
			return "", cli.Usagef("--id or --ref is required")
		}
	}
	if err := cli.ValidateID(id); err != nil {
		return "", err
	}
	return id, nil
}

// chainFor resolves a reference to its materialized layer directories, topmost first, which is
// the order every wclayer call wants for parentLayerPaths.
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
		if _, err := os.Stat(filepath.Join(p, "Files")); err != nil {
			return nil, cli.Usagef("layer %s is not materialized -- run image import", filepath.Base(p))
		}
		chain = append([]string{p}, chain...)
	}
	return chain, nil
}

// Stack prepares an already-created scratch layer over chain and returns its volume path.
// It is the process-isolated (argon) storage sequence -- ActivateLayer, PrepareLayer,
// GetLayerMountPath -- shared with internal/container. CreateScratchLayer, ExpandScratchSize
// and DestroyLayer stay with each caller.
//
// On failure Stack undoes what it has done so far, leaving a scratch layer that only
// DestroyLayer needs to remove.
func Stack(scratch string, chain []string) (string, error) {
	info := hcsshim.DriverInfo{}
	if err := hcsshim.ActivateLayer(info, scratch); err != nil {
		return "", fmt.Errorf("ActivateLayer: %w", err)
	}
	if err := hcsshim.PrepareLayer(info, scratch, chain); err != nil {
		_ = hcsshim.DeactivateLayer(info, scratch)
		return "", fmt.Errorf("PrepareLayer (needs an enabled BUILTIN\\Administrators SID): %w", err)
	}
	vol, err := hcsshim.GetLayerMountPath(info, scratch)
	if err != nil {
		_ = hcsshim.UnprepareLayer(info, scratch)
		_ = hcsshim.DeactivateLayer(info, scratch)
		return "", fmt.Errorf("GetLayerMountPath: %w", err)
	}
	return vol, nil
}

// Unstack reverses Stack: UnprepareLayer then DeactivateLayer. Every step is attempted even if
// the first fails, and the first error is returned. DestroyLayer stays with the caller.
func Unstack(scratch string) error {
	info := hcsshim.DriverInfo{}
	var first error
	if err := hcsshim.UnprepareLayer(info, scratch); err != nil {
		first = fmt.Errorf("UnprepareLayer: %w", err)
	}
	if err := hcsshim.DeactivateLayer(info, scratch); err != nil && first == nil {
		first = fmt.Errorf("DeactivateLayer: %w", err)
	}
	return first
}

type mountResult struct {
	OK      bool     `json:"ok"`
	Command string   `json:"command"`
	ID      string   `json:"id"`
	Ref     string   `json:"ref"`
	Volume  string   `json:"volume"`
	Scratch string   `json:"scratch"`
	Chain   []string `json:"chain"`
}

func mount(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--ref", "--id", "--store", "--scratch-size"); err != nil {
		return cli.Usage, err
	}
	ref, err := a.Require("--ref")
	if err != nil {
		return cli.Usage, err
	}
	var scratchSize uint64
	if v := a.Option("--scratch-size"); v != "" {
		if scratchSize, err = cli.ParseSize(v); err != nil {
			return cli.Usage, err
		}
	}
	st, err := store.New(a.Option("--store"))
	if err != nil {
		return cli.Failed, err
	}
	id, err := resolveID(a)
	if err != nil {
		return cli.Usage, err
	}

	chain, err := chainFor(st, ref)
	if err != nil {
		return exitFor(err), err
	}
	sp := scratchPath(st, id)
	if _, err := os.Stat(sp); err == nil {
		return cli.Usage, cli.Usagef("a mount named %q already exists at %s -- unmount it first", id, sp)
	}
	if err := os.MkdirAll(scratchRoot(st), 0o755); err != nil {
		return cli.Failed, err
	}

	e.Progress("chain:   %d layer(s), topmost %s", len(chain), filepath.Base(chain[0]))
	e.Progress("scratch: %s", sp)

	info := hcsshim.DriverInfo{}

	// Each step is undone in reverse on failure, so a half-built mount does not survive.
	if err := hcsshim.CreateScratchLayer(info, sp, "", chain); err != nil {
		return cli.Failed, fmt.Errorf("CreateScratchLayer (rerun elevated?): %w", err)
	}
	e.Progress("CreateScratchLayer ok")

	// Expand before Activate/Prepare, while nothing holds the vhd.
	if scratchSize != 0 {
		if err := hcsshim.ExpandScratchSize(info, sp, scratchSize); err != nil {
			_ = hcsshim.DestroyLayer(info, sp)
			return cli.Failed, fmt.Errorf("ExpandScratchSize: %w", err)
		}
		e.Progress("ExpandScratchSize to %d bytes ok", scratchSize)
	}

	vol, err := Stack(sp, chain)
	if err != nil {
		_ = hcsshim.DestroyLayer(info, sp)
		return cli.Failed, err
	}
	e.Progress("stacked layers ok")

	res := mountResult{
		OK: true, Command: "layer mount", ID: id, Ref: ref,
		Volume: vol, Scratch: sp, Chain: chain,
	}
	e.Result(res, func() {
		fmt.Printf("mounted %s\n  id:     %s\n  volume: %s\n", ref, id, vol)
	})
	return cli.OK, nil
}

func unmount(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--ref", "--store"); err != nil {
		return cli.Usage, err
	}
	st, err := store.New(a.Option("--store"))
	if err != nil {
		return cli.Failed, err
	}
	id, err := resolveID(a)
	if err != nil {
		return cli.Usage, err
	}
	sp := scratchPath(st, id)
	if _, err := os.Stat(sp); err != nil {
		return cli.Usage, cli.Usagef("no mount named %q at %s", id, sp)
	}

	info := hcsshim.DriverInfo{}

	// Every step is attempted even if an earlier one fails; the first error is reported.
	var firstErr error
	record := func(step string, err error) {
		if err != nil {
			e.Progress("%s: %v", step, err)
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", step, err)
			}
			return
		}
		e.Progress("%s ok", step)
	}
	record("Unstack", Unstack(sp))
	record("DestroyLayer", hcsshim.DestroyLayer(info, sp))

	// The post-condition, not the return value: DestroyLayer can report success and leave the
	// tree behind.
	if _, err := os.Stat(sp); err == nil {
		return cli.Failed, fmt.Errorf("scratch still present after DestroyLayer: %s", sp)
	}
	if firstErr != nil {
		return cli.Failed, firstErr
	}

	e.Result(map[string]any{"ok": true, "command": "layer unmount", "id": id}, func() {
		fmt.Printf("unmounted %s\n", id)
	})
	return cli.OK, nil
}

func list(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--store"); err != nil {
		return cli.Usage, err
	}
	st, err := store.New(a.Option("--store"))
	if err != nil {
		return cli.Failed, err
	}
	entries, err := os.ReadDir(scratchRoot(st))
	if err != nil && !os.IsNotExist(err) {
		return cli.Failed, err
	}

	type row struct {
		ID     string `json:"id"`
		Volume string `json:"volume"`
	}
	var rows []row
	for _, en := range entries {
		if !en.IsDir() {
			continue
		}
		sp := scratchPath(st, en.Name())
		vol, err := hcsshim.GetLayerMountPath(hcsshim.DriverInfo{}, sp)
		if err != nil {
			vol = fmt.Sprintf("(not mounted: %v)", err)
		}
		rows = append(rows, row{ID: en.Name(), Volume: vol})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })

	e.Result(map[string]any{"ok": true, "command": "layer ls", "mounts": rows}, func() {
		if len(rows) == 0 {
			fmt.Println("no mounts")
			return
		}
		for _, r := range rows {
			fmt.Printf("%-56s %s\n", r.ID, r.Volume)
		}
	})
	return cli.OK, nil
}

func exitFor(err error) int {
	if _, ok := err.(*cli.UsageError); ok {
		return cli.Usage
	}
	return cli.Failed
}
