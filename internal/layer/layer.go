//go:build windows

// Package layer is the `hcsctl layer` verb group: it turns a materialized image chain into a
// mounted volume.
//
// An imported image is read-only layer directories. To see the merged filesystem, the chain
// gets a computestorage scratch on top -- sandbox.vhdx from the base's blank.vhdx, attached
// with permanent lifetime, InitializeWritableLayer, then AttachLayerStorageFilter: the
// volume then presents the merged view. internal/scratch owns that sequence; this package
// is the ref-facing naming and bookkeeping over it.
//
// ELEVATED: the computestorage service refuses a filtered token.
package layer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/scratch"
	"github.com/joshmakestuff/hcsctl/internal/store"
	"github.com/joshmakestuff/hcsctl/internal/sysinfo"
	"github.com/spf13/cobra"
)

// Command is `hcsctl layer`.
func Command(e cli.Emit) *cobra.Command {
	return cli.Group("layer", "turn a materialized image chain into a mounted volume",
		mountCmd(e), unmountCmd(e), lsCmd(e))
}

func mountCmd(e cli.Emit) *cobra.Command {
	var ref, id, storeDir, scratchSize string
	cmd := &cobra.Command{
		Use:   "mount --ref <ref> [--id <id>] [--scratch-size 40GB] [--store <dir>]",
		Short: "put a writable scratch over a chain and print the volume path. ELEVATED",
		Long: `Put a computestorage scratch over a materialized chain with the layer storage
filter attached, then print the volume path. --scratch-size grows the scratch
beyond the default; it needs the SeManageVolumePrivilege grant. ELEVATED.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			var size uint64
			if scratchSize != "" {
				var err error
				if size, err = cli.ParseSize(scratchSize); err != nil {
					return err
				}
				if err := sysinfo.ExpandScratchReady(); err != nil {
					return err
				}
			}
			return mount(ref, id, storeDir, size, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &ref, "ref", "image reference, registry/repo:tag")
	cli.Required(cmd, "ref")
	cli.StringOnce(cmd.Flags(), &id, "id", "mount name; defaults to a name derived from --ref")
	cli.StringOnce(cmd.Flags(), &scratchSize, "scratch-size", "grow the scratch beyond the default, e.g. 40GB")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func unmountCmd(e cli.Emit) *cobra.Command {
	var ref, id, storeDir string
	cmd := &cobra.Command{
		Use:   "unmount --id <id> | --ref <ref> [--store <dir>]",
		Short: "detach the filter and destroy the scratch. ELEVATED",
		Args:  cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return unmount(id, ref, storeDir, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &id, "id", "mount name")
	cli.StringOnce(cmd.Flags(), &ref, "ref", "image reference; names the mount when --id is absent")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func lsCmd(e cli.Emit) *cobra.Command {
	var storeDir string
	cmd := &cobra.Command{
		Use:   "ls [--store <dir>]",
		Short: "mounts and their volume paths",
		Args:  cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return list(storeDir, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

// scratchRoot holds one directory per mount, named by its id.
func scratchRoot(st *store.Store) string { return filepath.Join(st.Root, "scratch") }

func scratchPath(st *store.Store, id string) string { return filepath.Join(scratchRoot(st), id) }

// idFor turns a reference into a usable directory name so `--id` can be optional.
func idFor(ref string) string {
	return strings.NewReplacer("/", "_", ":", "_", "@", "_", "\\", "_").Replace(ref)
}

// resolveID is the only way mount and unmount obtain an id, and it validates the id. An
// unvalidated id reaches the destroy path elevated (`--id ..` would name the store root).
func resolveID(id, ref string) (string, error) {
	if id == "" {
		if ref == "" {
			return "", cli.Usagef("--id or --ref is required")
		}
		id = idFor(ref)
	}
	if err := cli.ValidateID(id); err != nil {
		return "", err
	}
	return id, nil
}

// chainFor resolves a reference to its materialized layer directories, topmost first.
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

type mountResult struct {
	OK      bool     `json:"ok"`
	Command string   `json:"command"`
	ID      string   `json:"id"`
	Ref     string   `json:"ref"`
	Volume  string   `json:"volume"`
	Scratch string   `json:"scratch"`
	Chain   []string `json:"chain"`
}

func mount(ref, rawID, storeDir string, scratchSize uint64, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	id, err := resolveID(rawID, ref)
	if err != nil {
		return err
	}

	chain, err := chainFor(st, ref)
	if err != nil {
		return err
	}
	sp := scratchPath(st, id)
	if _, err := os.Stat(sp); err == nil {
		return cli.Usagef("a mount named %q already exists at %s -- unmount it first", id, sp)
	}
	if err := os.MkdirAll(scratchRoot(st), 0o755); err != nil {
		return err
	}

	e.Progress("chain:   %d layer(s), topmost %s", len(chain), filepath.Base(chain[0]))
	e.Progress("scratch: %s", sp)

	sc, err := scratch.Prepare(sp, chain, scratchSize, true)
	if err != nil {
		_ = scratch.Teardown(sp, false)
		return err
	}
	e.Progress("filter attached")

	res := mountResult{
		OK: true, Command: "layer mount", ID: id, Ref: ref,
		Volume: sc.Volume, Scratch: sp, Chain: chain,
	}
	e.Result(res, func() {
		fmt.Printf("mounted %s\n  id:     %s\n  volume: %s\n", ref, id, sc.Volume)
	})
	return nil
}

func unmount(rawID, ref, storeDir string, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	id, err := resolveID(rawID, ref)
	if err != nil {
		return err
	}
	sp := scratchPath(st, id)
	if _, err := os.Stat(sp); err != nil {
		return cli.Usagef("no mount named %q at %s", id, sp)
	}

	// Teardown detaches the filter and the VHD, destroys the layer, and
	// verifies absence.
	if err := scratch.Teardown(sp, true); err != nil {
		return err
	}

	e.Result(map[string]any{"ok": true, "command": "layer unmount", "id": id}, func() {
		fmt.Printf("unmounted %s\n", id)
	})
	return nil
}

func list(storeDir string, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(scratchRoot(st))
	if err != nil && !os.IsNotExist(err) {
		return err
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
		vol, err := scratch.Volume(scratchPath(st, en.Name()))
		if err != nil {
			vol = fmt.Sprintf("(not attached: %v)", err)
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
	return nil
}
