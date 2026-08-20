//go:build windows

// Package cim is the `cim` verb group: CIM filesystems via hcsshim's public pkg/cimfs.
//
// Two on-disk shapes. A standard CIM is a .cim file plus region_*/objectid_* files in the
// same directory; forks (create --fork-of) share those region files, so a fork is only
// usable next to its ancestors and destroying an ancestor breaks it. A block CIM packs
// everything into one container: a block-formatted regular file (--block <file>) or a raw
// block device (--block \\.\PhysicalDriveN). Merged and verified CIMs are block-only.
//
// Elevation, measured: create and merge are unprivileged -- unique in this tool. Mount and
// unmount need elevation; the specific right is unidentified (SeManageVolumePrivilege is
// not sufficient), so the requirement is documented, not gated.
//
// Known limits of the public surface: alternate-data-stream payloads cannot be written
// (create fails loudly on them) and extended attributes are not captured -- see writeTree.
// CimCreateFlagDoNotExpandPEImages and CimCreateFlagFixedSizeChunks are exported by
// pkg/cimfs but reachable through no public function, so no verb carries them.
package cim

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/osversion"
	"github.com/Microsoft/hcsshim/pkg/cimfs"
	"github.com/Microsoft/hcsshim/pkg/cimfs/format"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/spf13/cobra"
)

// Command is `hcsctl cim`.
func Command(e cli.Emit) *cobra.Command {
	return cli.Group("cim", "CIM filesystems via pkg/cimfs",
		createCmd(e), mountCmd(e), unmountCmd(e), mergeCmd(e), usageCmd(e), verifyCmd(e), destroyCmd(e))
}

func createCmd(e cli.Emit) *cobra.Command {
	var dir, cimPath, blockPath, name, forkOf string
	var unlinks, tombstones, mergedLinks []string
	var consistent, dataIntegrity bool
	cmd := &cobra.Command{
		Use: "create --dir <src> (--cim <path> | --block <path> [--name <cim-name>]) [--fork-of <name>]\n" +
			"           [--unlink <path>]... [--tombstone <path>]... [--merged-link <old>=<new>]...\n" +
			"           [--consistent] [--data-integrity]",
		Short: "build a CIM from a directory tree. Unelevated",
		Long: `Build a CIM from a directory tree: files with data and security descriptors,
directories, reparse points (not followed), hard links, empty alternate data
streams. A nonzero stream payload fails the build: it cannot be written through
public hcsshim pkg/cimfs (measured). Extended attributes are not captured.

--cim writes a standard CIM (the .cim plus region/objectid files land in its
directory); --fork-of forks from a sibling CIM in that directory, and --unlink
then removes inherited paths. Unlinking a nested path requires its parent
directory to exist in --dir too: without it the unlink is silently a no-op
(measured), which is why layer tars always carry parent directory entries.
--block writes a single-file or device block CIM;
--tombstone and --merged-link are merge-time operations recorded for later
cim merge; --consistent makes identical input produce an identical CIM;
--data-integrity seals the CIM on close and reports the root hash. Unelevated.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			links, err := parseMergedLinks(mergedLinks)
			if err != nil {
				return err
			}
			if (cimPath == "") == (blockPath == "") {
				return cli.Usagef("exactly one of --cim or --block is required")
			}
			if blockPath != "" {
				switch {
				case forkOf != "":
					return cli.Usagef("--fork-of forks a standard CIM; a block CIM cannot fork")
				case len(unlinks) > 0:
					return cli.Usagef("--unlink removes forked-parent content; it needs --cim with --fork-of")
				}
			} else {
				switch {
				case len(tombstones) > 0:
					return cli.Usagef("--tombstone is a merge-time operation; it needs --block")
				case len(links) > 0:
					return cli.Usagef("--merged-link is a merge-time operation; it needs --block")
				case consistent:
					return cli.Usagef("--consistent applies to block CIMs; it needs --block")
				case dataIntegrity:
					return cli.Usagef("--data-integrity applies to block CIMs; it needs --block")
				}
			}
			if len(unlinks) > 0 && forkOf == "" {
				return cli.Usagef("--unlink removes forked-parent content; it needs --fork-of")
			}
			if err := requireDir("--dir", dir); err != nil {
				return err
			}
			if cimPath != "" {
				return createStandard(dir, cimPath, forkOf, unlinks, e)
			}
			bcim, err := blockCIMFor("--block", blockPath, name)
			if err != nil {
				return err
			}
			if bcim.Type == cimfs.BlockCIMTypeSingleFile {
				if _, err := os.Stat(blockPath); err == nil {
					return cli.Usagef("--block %s already exists", blockPath)
				}
			}
			if err := requireBlockSupport(); err != nil {
				return err
			}
			if dataIntegrity {
				if err := requireVerifiedSupport(); err != nil {
					return err
				}
			}
			return createBlock(dir, bcim, tombstones, links, consistent, dataIntegrity, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &dir, "dir", "source directory tree")
	cli.Required(cmd, "dir")
	cli.StringOnce(cmd.Flags(), &cimPath, "cim", "standard CIM to create, e.g. E:\\cims\\base.cim")
	cli.StringOnce(cmd.Flags(), &blockPath, "block", "block CIM container: a new file, or \\\\.\\PhysicalDriveN")
	cli.StringOnce(cmd.Flags(), &name, "name", "CIM name inside the block container (default: block basename with .cim)")
	cli.StringOnce(cmd.Flags(), &forkOf, "fork-of", "sibling CIM name in the same directory to fork from")
	cli.StringArray(cmd.Flags(), &unlinks, "unlink", "path to remove from the forked view, repeatable")
	cli.StringArray(cmd.Flags(), &tombstones, "tombstone", "path to hide from lower layers at merge, repeatable")
	cli.StringArray(cmd.Flags(), &mergedLinks, "merged-link", "cross-CIM hard link <old>=<new>, resolved at merge, repeatable")
	cmd.Flags().BoolVar(&consistent, "consistent", false, "identical input produces an identical CIM")
	cmd.Flags().BoolVar(&dataIntegrity, "data-integrity", false, "seal the CIM on close and report the root hash")
	return cmd
}

type mergedLink struct{ old, new string }

func parseMergedLinks(vals []string) ([]mergedLink, error) {
	var links []mergedLink
	for _, v := range vals {
		old, new, found := strings.Cut(v, "=")
		if !found || old == "" || new == "" {
			return nil, cli.Usagef("--merged-link wants <old>=<new>, got %q", v)
		}
		links = append(links, mergedLink{old: old, new: new})
	}
	return links, nil
}

func createStandard(dir, cimPath, forkOf string, unlinks []string, e cli.Emit) error {
	imageDir := filepath.Dir(cimPath)
	newName := filepath.Base(cimPath)
	if newName == "." || newName == string(filepath.Separator) || strings.HasSuffix(cimPath, `\`) {
		return cli.Usagef("--cim %s has no file name", cimPath)
	}
	if forkOf != "" {
		if err := cli.ValidateID(forkOf); err != nil {
			return cli.Usagef("--fork-of %v", err)
		}
		if _, err := os.Stat(filepath.Join(imageDir, forkOf)); err != nil {
			return cli.Usagef("--fork-of %s: no such CIM in %s", forkOf, imageDir)
		}
	}
	dirExisted := true
	if _, err := os.Stat(imageDir); err != nil {
		dirExisted = false
	}
	if err := os.MkdirAll(imageDir, 0o755); err != nil {
		return err
	}

	w, err := cimfs.Create(imageDir, forkOf, newName)
	if err != nil {
		return fmt.Errorf("Create: %w", err)
	}
	// Abandoning a partial standard CIM: Close is the only way to release the handle and
	// it commits, so the partial artifact exists either way. A fresh fork is never
	// destroyed (DestroyCim would delete region files its parent shares) -- it is left
	// and named. A non-fork owns its region files exclusively: a directory this
	// invocation created is removed whole, and in a pre-existing directory the partial
	// CIM is destroyed, with one delayed retry because handles linger briefly after
	// close.
	undo := func(cause error) error {
		_ = w.Close()
		if forkOf != "" {
			return fmt.Errorf("%w (partial fork left at %s -- not auto-destroyed: destroying its region files would corrupt %s)",
				cause, cimPath, forkOf)
		}
		if !dirExisted {
			if rmErr := os.RemoveAll(imageDir); rmErr == nil {
				return cause
			}
		} else {
			if destroyErr := cimfs.DestroyCim(context.Background(), cimPath); destroyErr != nil {
				time.Sleep(3 * time.Second)
				destroyErr = cimfs.DestroyCim(context.Background(), cimPath)
				if destroyErr == nil {
					return cause
				}
			} else {
				return cause
			}
		}
		return fmt.Errorf("%w (partial CIM left at %s)", cause, cimPath)
	}

	st, err := writeTree(w, dir)
	if err != nil {
		return undo(err)
	}
	for _, p := range unlinks {
		if err := w.Unlink(p); err != nil {
			return undo(fmt.Errorf("Unlink %s: %w", p, err))
		}
	}
	if err := w.Close(); err != nil {
		return undo(fmt.Errorf("Close: %w", err))
	}

	doc := map[string]any{
		"ok": true, "command": "cim create", "cim": cimPath, "source": dir,
		"files": st.Files, "directories": st.Dirs, "links": st.Links,
		"streams": st.Streams, "bytes": st.Bytes,
	}
	if forkOf != "" {
		doc["forkOf"] = forkOf
	}
	if len(unlinks) > 0 {
		doc["unlinked"] = unlinks
	}
	e.Result(doc, func() {
		fmt.Printf("created %s\n  files=%d dirs=%d links=%d streams=%d bytes=%d\n",
			cimPath, st.Files, st.Dirs, st.Links, st.Streams, st.Bytes)
	})
	return nil
}

func createBlock(dir string, bcim *cimfs.BlockCIM, tombstones []string, links []mergedLink, consistent, dataIntegrity bool, e cli.Emit) error {
	if bcim.Type == cimfs.BlockCIMTypeSingleFile {
		if err := os.MkdirAll(filepath.Dir(bcim.BlockPath), 0o755); err != nil {
			return err
		}
	}
	var opts []cimfs.BlockCIMOpt
	if consistent {
		opts = append(opts, cimfs.WithConsistentCIM())
	}
	if dataIntegrity {
		opts = append(opts, cimfs.WithDataIntegrity())
	}
	w, err := cimfs.CreateBlockCIMWithOptions(context.Background(), bcim, opts...)
	if err != nil {
		return fmt.Errorf("CreateBlockCIMWithOptions: %w", err)
	}
	// A fresh single-file container is one file; a failed build removes it.
	undo := func(cause error) error {
		_ = w.Close()
		if bcim.Type == cimfs.BlockCIMTypeSingleFile {
			if rmErr := os.Remove(bcim.BlockPath); rmErr == nil {
				return cause
			}
		}
		return fmt.Errorf("%w (partial block CIM left at %s)", cause, bcim.BlockPath)
	}

	st, err := writeTree(w, dir)
	if err != nil {
		return undo(err)
	}
	for _, p := range tombstones {
		if err := w.AddTombstone(p); err != nil {
			return undo(fmt.Errorf("AddTombstone %s: %w", p, err))
		}
	}
	for _, l := range links {
		if err := w.AddMergedLink(l.old, l.new); err != nil {
			return undo(fmt.Errorf("AddMergedLink %s=%s: %w", l.old, l.new, err))
		}
	}
	if err := w.Close(); err != nil {
		return undo(fmt.Errorf("Close: %w", err))
	}

	doc := map[string]any{
		"ok": true, "command": "cim create", "source": dir,
		"files": st.Files, "directories": st.Dirs, "links": st.Links,
		"streams": st.Streams, "bytes": st.Bytes,
		"consistent": consistent, "dataIntegrity": dataIntegrity,
	}
	blockFields(doc, bcim)
	if len(tombstones) > 0 {
		doc["tombstones"] = tombstones
	}
	if len(links) > 0 {
		doc["mergedLinks"] = mergedLinks(links)
	}
	rootHash := ""
	if dataIntegrity {
		h, err := cimfs.GetVerificationInfo(bcim.BlockPath)
		if err != nil {
			return fmt.Errorf("created %s but GetVerificationInfo failed: %w", bcim, err)
		}
		rootHash = hex.EncodeToString(h)
		doc["rootHash"] = rootHash
	}
	e.Result(doc, func() {
		fmt.Printf("created %s (%s in %s)\n  files=%d dirs=%d links=%d streams=%d bytes=%d\n",
			bcim.CimName, blockTypeString(bcim.Type), bcim.BlockPath,
			st.Files, st.Dirs, st.Links, st.Streams, st.Bytes)
		if rootHash != "" {
			fmt.Printf("  rootHash=%s\n", rootHash)
		}
	})
	return nil
}

func mergedLinks(links []mergedLink) []string {
	var out []string
	for _, l := range links {
		out = append(out, l.old+"="+l.new)
	}
	return out
}

func mountCmd(e cli.Emit) *cobra.Command {
	var cimPath, blockPath, name, rootHash string
	var sources []string
	var dax, verified bool
	var guidFlag *cli.GUIDFlag
	cmd := &cobra.Command{
		Use: "mount (--cim <path> | --block <path> [--name <cim-name>]) [--source <block[::name]>]...\n" +
			"          [--guid <guid>] [--dax] [--verified] [--root-hash <64-hex>]",
		Short: "mount a CIM at a volume and print the volume path. ELEVATED",
		Long: `Mount a CIM at \\?\Volume{guid}\. The GUID defaults to a deterministic
derivation from the CIM's path, so the volume is recomputable from the command
line alone; --guid overrides it. --source (two or more, in the exact order given
to cim merge) mounts a merged block CIM. --verified mounts a sealed block CIM
with every read checked against the root hash: --root-hash pins the expected
hash; without it the hash is read from the CIM itself, which still exercises
verification but trusts the CIM being verified. ELEVATED.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if (cimPath == "") == (blockPath == "") {
				return cli.Usagef("exactly one of --cim or --block is required")
			}
			if len(sources) > 0 {
				if cimPath != "" {
					return cli.Usagef("--source mounts a merged block CIM; it needs --block")
				}
				if verified {
					return cli.Usagef("--verified and --source are exclusive: a merged mount is not a verified mount")
				}
				if len(sources) < 2 {
					return cli.Usagef("--source is needed at least twice: a merge has two or more sources")
				}
			}
			if verified && blockPath == "" {
				return cli.Usagef("--verified mounts a block CIM; it needs --block")
			}
			if rootHash != "" && !verified {
				return cli.Usagef("--root-hash needs --verified")
			}
			var hash []byte
			if rootHash != "" {
				var err error
				if hash, err = parseRootHash(rootHash); err != nil {
					return err
				}
			}
			if cimPath != "" {
				if err := requireFile("--cim", cimPath); err != nil {
					return err
				}
				return mountStandard(cimPath, guidFlag, dax, e)
			}
			bcim, err := blockCIMFor("--block", blockPath, name)
			if err != nil {
				return err
			}
			if bcim.Type == cimfs.BlockCIMTypeSingleFile {
				if err := requireFile("--block", blockPath); err != nil {
					return err
				}
			}
			srcs, err := parseSources(sources, bcim.Type)
			if err != nil {
				return err
			}
			if err := requireBlockSupport(); err != nil {
				return err
			}
			if len(srcs) > 0 {
				if err := requireMergedSupport(); err != nil {
					return err
				}
				return mountMerged(bcim, srcs, sources, guidFlag, dax, e)
			}
			if verified {
				if err := requireVerifiedSupport(); err != nil {
					return err
				}
				return mountVerified(bcim, hash, guidFlag, dax, e)
			}
			return mountBlock(bcim, guidFlag, dax, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &cimPath, "cim", "standard CIM to mount")
	cli.StringOnce(cmd.Flags(), &blockPath, "block", "block CIM container")
	cli.StringOnce(cmd.Flags(), &name, "name", "CIM name inside the block container (default: block basename with .cim)")
	cli.StringArray(cmd.Flags(), &sources, "source", "merge source <block[::name]>, repeatable, exact merge order")
	guidFlag = cli.GUID(cmd.Flags(), "guid", "volume GUID (default: derived from the CIM path)")
	cmd.Flags().BoolVar(&dax, "dax", false, "enable DAX for the mounted volume")
	cmd.Flags().BoolVar(&verified, "verified", false, "verified mount of a sealed block CIM")
	cli.StringOnce(cmd.Flags(), &rootHash, "root-hash", "expected root hash, 64 hex characters")
	return cmd
}

func parseSources(vals []string, wantType cimfs.BlockCIMType) ([]*cimfs.BlockCIM, error) {
	var srcs []*cimfs.BlockCIM
	for _, s := range vals {
		b, err := parseSource(s)
		if err != nil {
			return nil, err
		}
		if b.Type != wantType {
			return nil, cli.Usagef("--source %s is %s but the target is %s -- block CIM types must match",
				s, blockTypeString(b.Type), blockTypeString(wantType))
		}
		if b.Type == cimfs.BlockCIMTypeSingleFile {
			if err := requireFile("--source", b.BlockPath); err != nil {
				return nil, err
			}
		}
		srcs = append(srcs, b)
	}
	return srcs, nil
}

func mountFlags(dax bool) uint32 {
	if dax {
		return cimfs.CimMountFlagEnableDax
	}
	return cimfs.CimMountFlagNone
}

func mountStandard(cimPath string, guidFlag *cli.GUIDFlag, dax bool, e cli.Emit) error {
	abs, err := cimIdentity(cimPath)
	if err != nil {
		return err
	}
	g, err := volumeGUIDFor(guidFlag, abs)
	if err != nil {
		return err
	}
	vol, err := cimfs.Mount(abs, g, mountFlags(dax))
	if err != nil {
		return fmt.Errorf("Mount: %w", err)
	}
	return mountResult(e, vol, g, dax, map[string]any{"cim": cimPath})
}

func mountBlock(bcim *cimfs.BlockCIM, guidFlag *cli.GUIDFlag, dax bool, e cli.Emit) error {
	id, err := blockIdentity(bcim)
	if err != nil {
		return err
	}
	g, err := volumeGUIDFor(guidFlag, id)
	if err != nil {
		return err
	}
	flags := mountFlags(dax)
	switch bcim.Type {
	case cimfs.BlockCIMTypeSingleFile:
		flags |= cimfs.CimMountSingleFileCim
	case cimfs.BlockCIMTypeDevice:
		flags |= cimfs.CimMountBlockDeviceCim
	}
	vol, err := cimfs.Mount(filepath.Join(bcim.BlockPath, bcim.CimName), g, flags)
	if err != nil {
		return fmt.Errorf("Mount: %w", err)
	}
	doc := map[string]any{}
	blockFields(doc, bcim)
	return mountResult(e, vol, g, dax, doc)
}

func mountMerged(bcim *cimfs.BlockCIM, srcs []*cimfs.BlockCIM, sourceArgs []string, guidFlag *cli.GUIDFlag, dax bool, e cli.Emit) error {
	id, err := blockIdentity(bcim)
	if err != nil {
		return err
	}
	g, err := volumeGUIDFor(guidFlag, id)
	if err != nil {
		return err
	}
	vol, err := cimfs.MountMergedBlockCIMs(bcim, srcs, mountFlags(dax), g)
	if err != nil {
		return fmt.Errorf("MountMergedBlockCIMs: %w", err)
	}
	doc := map[string]any{"merged": true, "sources": sourceArgs}
	blockFields(doc, bcim)
	return mountResult(e, vol, g, dax, doc)
}

func mountVerified(bcim *cimfs.BlockCIM, hash []byte, guidFlag *cli.GUIDFlag, dax bool, e cli.Emit) error {
	id, err := blockIdentity(bcim)
	if err != nil {
		return err
	}
	g, err := volumeGUIDFor(guidFlag, id)
	if err != nil {
		return err
	}
	source := "caller"
	if hash == nil {
		source = "cim"
		if hash, err = cimfs.GetVerificationInfo(bcim.BlockPath); err != nil {
			return fmt.Errorf("GetVerificationInfo: %w", err)
		}
	}
	vol, err := cimfs.MountVerifiedBlockCIM(bcim, mountFlags(dax), g, hash)
	if err != nil {
		return fmt.Errorf("MountVerifiedBlockCIM: %w", err)
	}
	doc := map[string]any{
		"verified": true, "rootHash": hex.EncodeToString(hash), "rootHashSource": source,
	}
	blockFields(doc, bcim)
	return mountResult(e, vol, g, dax, doc)
}

func volumeGUIDFor(guidFlag *cli.GUIDFlag, identity string) (guid.GUID, error) {
	if guidFlag != nil && guidFlag.WasSet() {
		return guidFlag.Value(), nil
	}
	return mountGUID(identity)
}

// mountResult verifies the volume actually presents before reporting it; a mount that
// returned success but no volume is unmounted and reported as the failure it is.
func mountResult(e cli.Emit, vol string, g guid.GUID, dax bool, doc map[string]any) error {
	if _, err := os.Stat(vol); err != nil {
		_ = cimfs.Unmount(vol)
		return fmt.Errorf("mount returned %s but the volume is not accessible: %w", vol, err)
	}
	doc["ok"] = true
	doc["command"] = "cim mount"
	doc["volume"] = vol
	doc["guid"] = g.String()
	doc["dax"] = dax
	e.Result(doc, func() {
		fmt.Printf("mounted\n  volume: %s\n  guid:   %s\n", vol, g.String())
	})
	return nil
}

func unmountCmd(e cli.Emit) *cobra.Command {
	var volume, cimPath, blockPath, name string
	cmd := &cobra.Command{
		Use:   "unmount (--volume <\\\\?\\Volume{guid}\\> | --cim <path> | --block <path> [--name <cim-name>])",
		Short: "unmount a mounted CIM volume. ELEVATED",
		Long: `Unmount a CIM volume. --volume names it directly; --cim or --block recompute
the deterministic volume GUID cim mount derives, so a mount whose volume path
was lost is still unmountable from the same addressing. A mount made with an
explicit --guid must be unmounted by --volume. ELEVATED.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			given := 0
			for _, v := range []string{volume, cimPath, blockPath} {
				if v != "" {
					given++
				}
			}
			if given != 1 {
				return cli.Usagef("exactly one of --volume, --cim or --block is required")
			}
			switch {
			case volume != "":
				vol, g, err := parseVolumePath(volume)
				if err != nil {
					return err
				}
				return unmount(vol, g, e)
			case cimPath != "":
				id, err := cimIdentity(cimPath)
				if err != nil {
					return err
				}
				return unmountByIdentity(id, e)
			default:
				bcim, err := blockCIMFor("--block", blockPath, name)
				if err != nil {
					return err
				}
				id, err := blockIdentity(bcim)
				if err != nil {
					return err
				}
				return unmountByIdentity(id, e)
			}
		},
	}
	cli.StringOnce(cmd.Flags(), &volume, "volume", "mounted volume path, \\\\?\\Volume{guid}\\")
	cli.StringOnce(cmd.Flags(), &cimPath, "cim", "standard CIM whose derived volume to unmount")
	cli.StringOnce(cmd.Flags(), &blockPath, "block", "block CIM container whose derived volume to unmount")
	cli.StringOnce(cmd.Flags(), &name, "name", "CIM name inside the block container (default: block basename with .cim)")
	return cmd
}

func parseVolumePath(v string) (string, guid.GUID, error) {
	vol := v
	if !strings.HasSuffix(vol, `\`) {
		vol += `\`
	}
	if !strings.HasPrefix(vol, `\\?\Volume{`) || !strings.HasSuffix(vol, `}\`) {
		return "", guid.GUID{}, cli.Usagef(`--volume %s is not a \\?\Volume{guid}\ path`, v)
	}
	g, err := guid.FromString(strings.TrimSuffix(strings.TrimPrefix(vol, `\\?\Volume{`), `}\`))
	if err != nil {
		return "", guid.GUID{}, cli.Usagef("--volume %s: %v", v, err)
	}
	return vol, g, nil
}

func unmountByIdentity(identity string, e cli.Emit) error {
	g, err := mountGUID(identity)
	if err != nil {
		return err
	}
	return unmount(fmt.Sprintf(`\\?\Volume{%s}\`, g.String()), g, e)
}

func unmount(vol string, g guid.GUID, e cli.Emit) error {
	if err := cimfs.Unmount(vol); err != nil {
		return fmt.Errorf("Unmount: %w", err)
	}
	if _, err := os.Stat(vol); err == nil {
		return fmt.Errorf("Unmount returned success but %s still exists", vol)
	}
	e.Result(map[string]any{
		"ok": true, "command": "cim unmount", "volume": vol, "guid": g.String(),
	}, func() {
		fmt.Printf("unmounted %s\n", vol)
	})
	return nil
}

func mergeCmd(e cli.Emit) *cobra.Command {
	var blockPath, name string
	var sources []string
	var consistent, dataIntegrity bool
	cmd := &cobra.Command{
		Use: "merge --block <out> [--name <cim-name>] --source <block[::name]> --source <...>\n" +
			"          [--consistent] [--data-integrity]",
		Short: "merge block CIMs into a new merged CIM. Unelevated",
		Long: `Merge two or more block CIMs into a new merged block CIM. Sources are given
topmost first: a path in an earlier source shadows the same path in later ones,
and a tombstone in an earlier source hides it entirely. The merge records
metadata only -- mounting the result needs the same sources in the same order.
Unelevated.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			bcim, err := blockCIMFor("--block", blockPath, name)
			if err != nil {
				return err
			}
			if len(sources) < 2 {
				return cli.Usagef("--source is needed at least twice: a merge has two or more sources")
			}
			srcs, err := parseSources(sources, bcim.Type)
			if err != nil {
				return err
			}
			if bcim.Type == cimfs.BlockCIMTypeSingleFile {
				if _, err := os.Stat(blockPath); err == nil {
					return cli.Usagef("--block %s already exists", blockPath)
				}
			}
			if err := requireMergedSupport(); err != nil {
				return err
			}
			if dataIntegrity {
				if err := requireVerifiedSupport(); err != nil {
					return err
				}
			}
			return merge(bcim, srcs, sources, consistent, dataIntegrity, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &blockPath, "block", "merged block CIM container to create")
	cli.Required(cmd, "block")
	cli.StringOnce(cmd.Flags(), &name, "name", "CIM name inside the block container (default: block basename with .cim)")
	cli.StringArray(cmd.Flags(), &sources, "source", "source <block[::name]>, topmost first, repeatable")
	cmd.Flags().BoolVar(&consistent, "consistent", false, "identical input produces an identical CIM")
	cmd.Flags().BoolVar(&dataIntegrity, "data-integrity", false, "seal the merged CIM and report the root hash")
	return cmd
}

func merge(bcim *cimfs.BlockCIM, srcs []*cimfs.BlockCIM, sourceArgs []string, consistent, dataIntegrity bool, e cli.Emit) error {
	if bcim.Type == cimfs.BlockCIMTypeSingleFile {
		if err := os.MkdirAll(filepath.Dir(bcim.BlockPath), 0o755); err != nil {
			return err
		}
	}
	var opts []cimfs.BlockCIMOpt
	if consistent {
		opts = append(opts, cimfs.WithConsistentCIM())
	}
	if dataIntegrity {
		opts = append(opts, cimfs.WithDataIntegrity())
	}
	if err := cimfs.MergeBlockCIMsWithOpts(context.Background(), bcim, srcs, opts...); err != nil {
		if bcim.Type == cimfs.BlockCIMTypeSingleFile {
			if rmErr := os.Remove(bcim.BlockPath); rmErr != nil && !os.IsNotExist(rmErr) {
				return fmt.Errorf("MergeBlockCIMs: %w (partial block CIM left at %s)", err, bcim.BlockPath)
			}
		}
		return fmt.Errorf("MergeBlockCIMs: %w", err)
	}

	doc := map[string]any{
		"ok": true, "command": "cim merge", "sources": sourceArgs,
		"consistent": consistent, "dataIntegrity": dataIntegrity,
	}
	blockFields(doc, bcim)
	rootHash := ""
	if dataIntegrity {
		h, err := cimfs.GetVerificationInfo(bcim.BlockPath)
		if err != nil {
			return fmt.Errorf("merged %s but GetVerificationInfo failed: %w", bcim, err)
		}
		rootHash = hex.EncodeToString(h)
		doc["rootHash"] = rootHash
	}
	e.Result(doc, func() {
		fmt.Printf("merged %d sources into %s (%s in %s)\n",
			len(srcs), bcim.CimName, blockTypeString(bcim.Type), bcim.BlockPath)
		if rootHash != "" {
			fmt.Printf("  rootHash=%s\n", rootHash)
		}
	})
	return nil
}

func usageCmd(e cli.Emit) *cobra.Command {
	var cimPath string
	cmd := &cobra.Command{
		Use:   "usage --cim <path>",
		Short: "on-disk bytes of a standard CIM's region and objectid files. Unelevated",
		Long: `Total on-disk bytes of the region and objectid files a standard CIM's header
names. Forked CIMs share region files, so the usages of a fork and its parent
overlap. A block CIM is one container file; its size is its usage, and this
verb rejects it. Unelevated.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := requireStandardCim("--cim", cimPath); err != nil {
				return err
			}
			u, err := cimfs.GetCimUsage(context.Background(), cimPath)
			if err != nil {
				return fmt.Errorf("GetCimUsage: %w", err)
			}
			e.Result(map[string]any{
				"ok": true, "command": "cim usage", "cim": cimPath, "usageBytes": u,
			}, func() {
				fmt.Printf("%s uses %d bytes\n", cimPath, u)
			})
			return nil
		},
	}
	cli.StringOnce(cmd.Flags(), &cimPath, "cim", "standard CIM file")
	cli.Required(cmd, "cim")
	return cmd
}

func verifyCmd(e cli.Emit) *cobra.Command {
	var blockPath string
	cmd := &cobra.Command{
		Use:   "verify --block <path>",
		Short: "root hash of a sealed block CIM. Unelevated",
		Long: `Read the verification info of a block CIM: whether it is sealed and, if so,
the root hash a verified mount checks reads against. An unsealed CIM is a
run failure, not a usage error: the question was asked and answered. Unelevated.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if !isDevicePath(blockPath) {
				if err := requireFile("--block", blockPath); err != nil {
					return err
				}
			}
			h, err := cimfs.GetVerificationInfo(blockPath)
			if err != nil {
				return fmt.Errorf("GetVerificationInfo: %w", err)
			}
			e.Result(map[string]any{
				"ok": true, "command": "cim verify", "block": blockPath,
				"sealed": true, "rootHash": hex.EncodeToString(h),
			}, func() {
				fmt.Printf("%s is sealed\n  rootHash=%s\n", blockPath, hex.EncodeToString(h))
			})
			return nil
		},
	}
	cli.StringOnce(cmd.Flags(), &blockPath, "block", "block CIM container")
	cli.Required(cmd, "block")
	return cmd
}

func destroyCmd(e cli.Emit) *cobra.Command {
	var cimPath string
	cmd := &cobra.Command{
		Use:   "destroy --cim <path>",
		Short: "delete a standard CIM and its region/objectid files. Unelevated",
		Long: `Delete a standard CIM: the .cim file and the region and objectid files its
header names, verified absent afterwards. Any CIM forked off the destroyed one
becomes unusable -- destroy forks before their parents. A block CIM is one
container file; os.Remove/del is sufficient, and this verb rejects it.
Unelevated.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := requireStandardCim("--cim", cimPath); err != nil {
				return err
			}
			if err := cimfs.DestroyCim(context.Background(), cimPath); err != nil {
				return fmt.Errorf("DestroyCim: %w", err)
			}
			if _, err := os.Stat(cimPath); err == nil {
				return fmt.Errorf("DestroyCim returned success but %s still exists", cimPath)
			}
			e.Result(map[string]any{
				"ok": true, "command": "cim destroy", "cim": cimPath,
			}, func() {
				fmt.Printf("destroyed %s\n", cimPath)
			})
			return nil
		},
	}
	cli.StringOnce(cmd.Flags(), &cimPath, "cim", "standard CIM file to destroy")
	cli.Required(cmd, "cim")
	return cmd
}

// --- shared shapes ---

func blockFields(doc map[string]any, b *cimfs.BlockCIM) {
	doc["block"] = b.BlockPath
	doc["name"] = b.CimName
	doc["blockType"] = blockTypeString(b.Type)
}

func blockTypeString(t cimfs.BlockCIMType) string {
	switch t {
	case cimfs.BlockCIMTypeSingleFile:
		return "single-file"
	case cimfs.BlockCIMTypeDevice:
		return "device"
	default:
		return "none"
	}
}

func requireDir(name, v string) error {
	if err := cli.Require(name, v); err != nil {
		return err
	}
	fi, err := os.Stat(v)
	if err != nil {
		return cli.Usagef("%s %s: %v", name, v, err)
	}
	if !fi.IsDir() {
		return cli.Usagef("%s %s is not a directory", name, v)
	}
	return nil
}

func requireFile(name, v string) error {
	if err := cli.Require(name, v); err != nil {
		return err
	}
	fi, err := os.Stat(v)
	if err != nil {
		return cli.Usagef("%s %s: %v", name, v, err)
	}
	if fi.IsDir() {
		return cli.Usagef("%s %s is a directory, not a CIM file", name, v)
	}
	return nil
}

// requireStandardCim sniffs the standard-CIM magic, so a block container handed to a
// standard-only verb (usage, destroy) is a usage error naming the actual mistake instead
// of a run failure deep in region-file discovery.
func requireStandardCim(name, v string) error {
	if err := requireFile(name, v); err != nil {
		return err
	}
	f, err := os.Open(v)
	if err != nil {
		return cli.Usagef("%s %s: %v", name, v, err)
	}
	defer f.Close()
	var magic [8]byte
	if _, err := f.Read(magic[:]); err != nil {
		return cli.Usagef("%s %s is not a CIM: %v", name, v, err)
	}
	if !bytes.Equal(magic[:], format.MagicValue[:]) {
		return cli.Usagef("%s %s is not a standard CIM -- for a block CIM the container file's size is its usage and deleting the file destroys it", name, v)
	}
	return nil
}

func requireBlockSupport() error {
	if !cimfs.IsBlockCimSupported() {
		return cli.Usagef("block CIMs are not supported on this host (build %d; hcsshim gates them at 27766)", osversion.Build())
	}
	return nil
}

func requireMergedSupport() error {
	if !cimfs.IsMergedCimSupported() {
		return cli.Usagef("merged CIMs are not supported on this host (build %d; hcsshim gates them at 27766)", osversion.Build())
	}
	return nil
}

func requireVerifiedSupport() error {
	if !cimfs.IsVerifiedCimSupported() {
		return cli.Usagef("verified CIMs are not supported on this host (build %d; hcsshim gates them at 27800)", osversion.Build())
	}
	return nil
}
