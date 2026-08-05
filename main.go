//go:build windows

// hcsctl is a CLI over the Windows Host Compute Service, built on Microsoft/hcsshim.
//
// The goal is to surface HCS -- images, layers, compute systems, networking -- as a tool you
// can drive from a shell or an agent. Image preparation is what works today; the rest is
// roadmap, not vapour: hcsshim already exposes the layer runtime (ActivateLayer, PrepareLayer,
// GetLayerMountPath), compute systems (CreateContainer with HvPartition), CimFS, and 228
// networking functions in the hcn package. Verbs get added over those.
//
// Two rules this repo is built to:
//
//	Public packages only. pkg/*, the hcsshim root package, computestorage, osversion. Needing
//	internal/ is a signal to reconsider the design, not to fork.
//
//	Every verb honours the same contract: --json puts exactly one document on stdout with
//	progress on stderr, and exit codes mean 0 ok, 1 ran and failed, 64 bad arguments with
//	nothing attempted.
package main

import (
	"fmt"
	"os"

	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/container"
	"github.com/joshmakestuff/hcsctl/internal/image"
	"github.com/joshmakestuff/hcsctl/internal/layer"
	"github.com/joshmakestuff/hcsctl/internal/sysinfo"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(argv []string) int {
	// Read --json off argv rather than off the parse: a malformed command line must still be
	// reported in the shape the caller asked for, and the parse is what may have failed.
	wantJSON := false
	for _, a := range argv {
		if a == "--json" {
			wantJSON = true
		}
	}
	e := cli.Emit{JSON: wantJSON}

	args, err := cli.Parse(argv, "--json", "--blobs", "--keep", "--force")
	if err != nil {
		e.Failure("usage", err)
		usage()
		return cli.Usage
	}

	if len(args.Words) == 0 {
		usage()
		return cli.Usage
	}

	var code int
	switch args.Word(0) {
	case "image":
		code, err = image.Dispatch(args, e)
	case "layer":
		code, err = layer.Dispatch(args, e)
	case "container":
		code, err = container.Dispatch(args, e)
	case "info":
		code, err = sysinfo.Run(args, e)
	default:
		err = cli.Usagef("unknown verb group %q (expected: image, layer, container, info)", args.Word(0))
		code = cli.Usage
	}

	if err != nil {
		stage := "run"
		var ue *cli.UsageError
		if errorsAs(err, &ue) {
			stage = "usage"
		}
		e.Failure(stage, err)
		if code == cli.Usage {
			usage()
		}
		return code
	}
	return code
}

// errorsAs avoids importing errors just for one call site in this file.
func errorsAs(err error, target **cli.UsageError) bool {
	if ue, ok := err.(*cli.UsageError); ok {
		*target = ue
		return true
	}
	return false
}

func usage() {
	fmt.Fprint(os.Stderr, `hcsctl -- a CLI over the Windows Host Compute Service

usage: hcsctl <group> <verb> [options]

  image pull   --ref <registry/repo:tag> [--store <dir>]
               Fetch a Windows base image's layers into the store, digest-verified while
               streaming. Unelevated.

  image import --ref <ref> [--store <dir>]
               Materialize pulled layers into bootable layer directories and write
               layerchain.json. ELEVATED: extraction needs SeBackup/SeRestore, and
               ProcessBaseLayer needs an enabled BUILTIN\Administrators SID, which is a
               group check no user-rights grant satisfies.

  image ls     [--store <dir>]                 What the store holds. Unelevated.
  image rm     --ref <ref> [--blobs] [--store <dir>]
               Remove materialized layers via DestroyLayer. ELEVATED.

  layer mount   --ref <ref> [--id <id>] [--store <dir>]
               Put a writable scratch layer over a materialized chain, activate and prepare
               it, then print the volume path. ELEVATED.

  layer unmount --id <id> | --ref <ref> [--store <dir>]
               Unprepare, deactivate and destroy the scratch. ELEVATED.

  layer ls      [--store <dir>]                Mounts and their volume paths.

  container run    --ref <ref> [--cmd "<cmdline>"] [--id <id>] [--cpus N]
                   [--memory-mb N] [--hostname H] [--cwd D] [--user U] [--keep]
               Create, boot and run one command in a Hyper-V-isolated container, then tear
               it down. --cmd defaults to "cmd /c ver". ELEVATED.

  container create --ref <ref> [--id <id>] [--cpus N] [--memory-mb N] [--hostname H]
  container start  --id <id> | --ref <ref>
  container exec   --id <id> --cmd "<cmdline>" [--cwd D] [--user U]
  container stop   --id <id> [--force]
  container rm     --id <id> [--force]
  container ls     [--store <dir>]             Containers and their HCS state.

  info         Host build, CimFS support, elevation and privilege state. Unelevated.

global options:
  --json       One JSON document on stdout; progress on stderr.

exit codes: 0 ok, 1 ran and failed, 64 bad arguments (nothing attempted)
             a guest process's own exit code is reported as exitCode in the result, not as
             hcsctl's exit code

Planned, not built: network (hcn), cim, process-isolated containers. See the roadmap issue.
`)
}
