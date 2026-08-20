//go:build windows

// Package image is the `hcsctl image` verb group: getting a Windows container base image from
// a registry onto disk in a form HCS can boot.
//
// Registry work is go-containerregistry; hcsshim does not do it. Layer materialization is
// hcsshim's pkg/ociwclayer, which extracts the tar AND finalizes -- baseLayerWriter.Close()
// calls ProcessBaseLayer and ProcessUtilityVMImage.
package image

import (
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/spf13/cobra"
)

// Command is `hcsctl image`.
func Command(e cli.Emit) *cobra.Command {
	return cli.Group("image", "get a base image from a registry onto disk",
		pullCmd(e), importCmd(e), lsCmd(e), rmCmd(e))
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
	var ref, storeDir string
	cmd := &cobra.Command{
		Use:   "import --ref <ref> [--store <dir>]",
		Short: "materialize pulled layers into bootable layer directories. ELEVATED",
		Long: `Materialize pulled layers into bootable layer directories and write
layerchain.json. ELEVATED: extraction needs SeBackup/SeRestore, and
ProcessBaseLayer needs an enabled BUILTIN\Administrators SID, which is a
group check no user-rights grant satisfies.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return importImage(ref, storeDir, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &ref, "ref", "image reference, registry/repo:tag")
	cli.Required(cmd, "ref")
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
