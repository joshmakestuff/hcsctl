//go:build windows

// Package image is the `hcsctl image` verb group: getting a Windows container base image from
// a registry onto disk in a form HCS can boot.
//
// Registry work is go-containerregistry. Layer materialization is the modern
// computestorage pipeline: internal/transport stages each blob to the HCS
// transport format, HcsImportLayer materializes it, and SetupContainerBaseLayer
// (+ SetupUtilityVMBaseLayer) completes the base. No wclayer anywhere.
package image

import (
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/spf13/cobra"
)

// Command is `hcsctl image`.
func Command(e cli.Emit) *cobra.Command {
	return cli.Group("image", "get a base image from a registry onto disk",
		pullCmd(e), importCmd(e), exportCmd(e), lsCmd(e), rmCmd(e))
}

func pullCmd(e cli.Emit) *cobra.Command {
	var ref, storeDir string
	cmd := &cobra.Command{
		Use:   "pull --ref <registry/repo:tag> [--store <dir>]",
		Short: "fetch a base image's layers into the store",
		Long: `Fetch a Windows base image's layers into the store, digest-verified while
streaming. Unelevated.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return pull(ref, storeDir, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &ref, "ref", "image reference, registry/repo:tag")
	cli.Required(cmd, "ref")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func importCmd(e cli.Emit) *cobra.Command {
	var ref, storeDir, sizeStr string
	cmd := &cobra.Command{
		Use:   "import --ref <ref> [--base-size-gb N] [--store <dir>]",
		Short: "materialize pulled layers into bootable layer directories. ELEVATED",
		Long: `Materialize pulled layers into bootable layer directories: each blob is
staged to the HCS transport format and imported with HcsImportLayer; the base
is completed with SetupContainerBaseLayer (and SetupUtilityVMBaseLayer when
the image carries a utility VM). ELEVATED: the computestorage service refuses
a filtered token, and the import runs under SeBackup/SeRestore.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			size := uint64(10)
			if sizeStr != "" {
				var err error
				if size, err = cli.ParseUint(sizeStr, 2048); err != nil {
					return cli.Usagef("--base-size-gb %v", err)
				}
			}
			return importImage(ref, storeDir, size, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &ref, "ref", "image reference, registry/repo:tag")
	cli.Required(cmd, "ref")
	cli.StringOnce(cmd.Flags(), &sizeStr, "base-size-gb", "base VHD size in GB (default 10)")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func exportCmd(e cli.Emit) *cobra.Command {
	var ref, out, storeDir string
	cmd := &cobra.Command{
		Use:   "export --ref <ref> --out <dir> [--store <dir>]",
		Short: "export a materialized image as OCI layer tars. ELEVATED",
		Long: `Export every materialized layer of an image, base to top, as one uncompressed
OCI layer tar each. ELEVATED: export reads layers with SeBackupPrivilege and
temporarily activates and prepares each layer; a layer mounted elsewhere fails
with an actionable error. The output directory must not exist; export stages in
a temporary sibling and publishes only after every layer succeeds.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return exportImage(ref, out, storeDir, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &ref, "ref", "image reference, registry/repo:tag")
	cli.Required(cmd, "ref")
	cli.StringOnce(cmd.Flags(), &out, "out", "output directory (must not exist)")
	cli.Required(cmd, "out")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func lsCmd(e cli.Emit) *cobra.Command {
	var storeDir string
	cmd := &cobra.Command{
		Use:   "ls [--store <dir>]",
		Short: "what the store holds. Unelevated",
		Args:  cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return list(storeDir, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func rmCmd(e cli.Emit) *cobra.Command {
	var ref, storeDir string
	var blobs bool
	cmd := &cobra.Command{
		Use:   "rm --ref <ref> [--blobs] [--store <dir>]",
		Short: "remove materialized layers via DestroyLayer. ELEVATED",
		Args:  cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return remove(ref, storeDir, blobs, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &ref, "ref", "image reference, registry/repo:tag")
	cli.Required(cmd, "ref")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	cmd.Flags().BoolVar(&blobs, "blobs", false, "also remove the downloaded blobs")
	return cmd
}
