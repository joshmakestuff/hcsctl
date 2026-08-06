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
	"github.com/joshmakestuff/hcsctl/internal/network"
	"github.com/joshmakestuff/hcsctl/internal/storage"
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

	args, err := cli.Parse(argv, "--json", "--blobs", "--keep", "--force", "--writable")
	if err != nil {
		e.Failure("usage", err)
		usage()
		return cli.Usage
	}

	if len(args.Words) == 0 {
		// Failure before usage, so `hcsctl --json` still puts its one document on stdout --
		// the contract holds on every path, including the empty one.
		e.Failure("usage", cli.Usagef("a verb group is required (image, layer, container, network, info)"))
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
	case "network":
		code, err = network.Dispatch(args, e)
	case "storage":
		code, err = storage.Dispatch(args, e)
	case "info":
		code, err = sysinfo.Run(args, e)
	default:
		err = cli.Usagef("unknown verb group %q (expected: image, layer, container, network, storage, info)", args.Word(0))
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

  layer mount   --ref <ref> [--id <id>] [--scratch-size 40GB] [--store <dir>]
               Put a writable scratch layer over a materialized chain, activate and prepare
               it, then print the volume path. --scratch-size grows the scratch beyond the
               default via ExpandScratchSize. ELEVATED.

  layer unmount --id <id> | --ref <ref> [--store <dir>]
               Unprepare, deactivate and destroy the scratch. ELEVATED.

  layer ls      [--store <dir>]                Mounts and their volume paths.

  container run    --ref <ref> [--cmd "<cmdline>"] [--id <id>] [--cpus N]
                   [--memory-mb N] [--hostname H] [--cwd D] [--user U]
                   [--env NAME=value]... [--network <name|id>] [--dns-search list]
                   [--mount HOST:CONTAINER[:ro]]... [--scratch-size 40GB] [--keep]
               Create, boot and run one command in a Hyper-V-isolated container, then tear
               it down. --cmd defaults to "cmd /c ver". --network attaches an endpoint on
               an existing host compute network and reports its address. --mount maps a host
               directory into the guest over VSMB -- not a bind mount, and not Docker
               semantics; both paths drive-letter absolute. ELEVATED.

  container create --ref <ref> [--id <id>] [--cpus N] [--memory-mb N] [--hostname H]
                   [--network <name|id>] [--dns-search list] [--mount HOST:CONTAINER[:ro]]...
                   [--scratch-size 40GB]
               --scratch-size grows the scratch VHD so the guest's C: is bigger than the
               default -- anything writing real data wants this.
  container start  --id <id> | --ref <ref>
  container exec   --id <id> --cmd "<cmdline>" [--cwd D] [--user U] [--env NAME=value]...
                   [--timeout 30s]
               Without --timeout, waits for the guest process forever -- that is how a
               caller follows a long-running app's output. With it, the process is killed
               on expiry and the result reports timedOut=true with a null exitCode.

  container kill   --id <id> --pid <pid>
               Kill one guest process and confirm it is gone. PIDs come from container ps
               or the exec result. Kill (and --timeout) terminates that process only: a
               cmd /c wrapper's children survive it, so exec the target directly when a
               kill must be total.
  container stop   --id <id> [--force]
  container rm     --id <id> [--force]
  container ls     [--store <dir>]             Containers and their HCS state.
  container stats   --id <id>                  Uptime, memory, CPU, storage and network.
  container ps      --id <id>                  Processes running in the guest.
  container inspect --id <id>                  What the store and HCS each know.
  container pause   --id <id>
  container resume  --id <id>

  storage setup-base --layer <dir> [--size-gb N]
               Prepare a base layer for VHD-backed (computestorage) use: blank-base.vhdx and
               blank.vhdx created inside the layer directory. MUTATES the layer -- Hives/ and
               Layout are regenerated -- so point it at a copy, not a store layer. ELEVATED.

  storage mount   --base <dir> --scratch-dir <dir> [--parent <dir>]...
  storage mount   --ref <ref> --scratch-dir <dir> [--store <dir>]
               Copy blank.vhdx to sandbox.vhdx (first time), attach it, initialize the
               writable layer and attach the storage filter. Prints the volume carrying the
               merged view. Parents topmost first; defaults to the base. --ref resolves a
               store image's chain instead -- store base layers already carry blank.vhdx
               (wclayer import creates it), so nothing mutates the store. ELEVATED.

  storage unmount --scratch-dir <dir>
               Detach the storage filter and the scratch VHD. ELEVATED.

  storage export  --layer <volume> --dest <existing-dir> [--parent <dir>]... [--writable]
               HcsExportLayer. Measured working: a *mounted* writable layer's volume path
               with --writable, producing Files/Hives/tombstones. A legacy (wclayer)
               directory layer fails partway -- the legacy variants are not public hcsshim.
  storage import  --source <dir> --layer <dest-dir> [--parent <dir>]...
               HcsImportLayer. NOT YET SEEN WORKING -- fails path-not-found after writing
               Files; destination semantics under investigation, see issue #18. ELEVATED.

  storage destroy --layer <dir>
               HcsDestroyLayer, verified by directory absence. Layer directories defeat
               ordinary deletion (restored security descriptors); this is the tool that
               removes them. ELEVATED.

  network ls        Host compute networks, their subnets and endpoint counts. Unelevated.
  network endpoints [--network <name|id>]      Endpoints and their addresses. Unelevated.

  info         [--store <dir>]
               Host build and capability: CimFS support, elevation, Hyper-V Administrators
               membership, privilege state, vmcompute/vmms/hvhost service states, the store,
               and per-image process-isolation compatibility. Unelevated.

global options:
  --json       One JSON document on stdout; progress on stderr.

exit codes: 0 ok, 1 ran and failed, 64 bad arguments (nothing attempted)
             a guest process's own exit code is reported as exitCode in the result, not as
             hcsctl's exit code

Planned, not built: network (hcn), cim, process-isolated containers. See the roadmap issue.
`)
}
