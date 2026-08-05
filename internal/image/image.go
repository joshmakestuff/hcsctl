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
)

// Dispatch routes `hcsctl image <verb>`.
func Dispatch(a *cli.Args, e cli.Emit) (int, error) {
	switch a.Word(1) {
	case "pull":
		return pull(a, e)
	case "import":
		return importImage(a, e)
	case "ls":
		return list(a, e)
	case "rm":
		return remove(a, e)
	case "":
		return cli.Usage, cli.Usagef("image needs a subcommand: pull, import, ls, rm")
	default:
		return cli.Usage, cli.Usagef("unknown image subcommand %q (expected pull, import, ls, rm)", a.Word(1))
	}
}
