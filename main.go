//go:build windows

// hcsctl is a CLI over the Windows Host Compute Service, built on Microsoft/hcsshim.
//
// It surfaces HCS -- images, layers, compute systems, networking -- as a tool you can drive
// from a shell or an agent.
//
// Two rules this repo is built to:
//
//	Public hcsshim packages only. pkg/*, the hcsshim root package, computestorage, osversion.
//	Where hcsshim exports no public equivalent -- the v2 compute-system API that `vm` needs --
//	bind the documented Windows entry point in vmcompute.dll directly. Copying or vendoring
//	hcsshim's internal/ source is out.
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
	"github.com/joshmakestuff/hcsctl/internal/guest"
	"github.com/joshmakestuff/hcsctl/internal/image"
	"github.com/joshmakestuff/hcsctl/internal/layer"
	"github.com/joshmakestuff/hcsctl/internal/network"
	"github.com/joshmakestuff/hcsctl/internal/storage"
	"github.com/joshmakestuff/hcsctl/internal/sysinfo"
	"github.com/joshmakestuff/hcsctl/internal/vm"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(argv []string) int {
	// Read --json off argv, not off the parse: a malformed command line must still be
	// reported in the shape the caller asked for.
	wantJSON, wantStream := false, false
	for _, a := range argv {
		if a == "--json" {
			wantJSON = true
		}
		if a == "--stream-json" {
			wantStream = true
		}
	}
	e := cli.Emit{JSON: wantJSON, StreamJSON: wantStream}

	// help and version are answered before the parser runs: --help would otherwise be "an
	// option requiring a value" and -h is not an option at all. Leading position only: an
	// option's *value* may be the string "--help".
	if len(argv) > 0 {
		switch argv[0] {
		case "--help", "-h", "help":
			return helpCmd(e)
		case "--version", "version":
			return versionCmd(e)
		}
	}

	args, err := cli.Parse(argv, "--json", "--stream-json", "--blobs", "--keep", "--force", "--writable", "--follow", "--no-copy-on-write", "--no-input", "--all", "--interactive", "--tty")
	if err != nil {
		e.Failure("usage", err)
		usage()
		return cli.Usage
	}

	if len(args.Words) == 0 {
		// Failure before usage, so `hcsctl --json` still puts its one document on stdout.
		e.Failure("usage", cli.Usagef("a verb group is required (image, layer, container, vm, guest, network, storage, info)"))
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
	case "vm":
		code, err = vm.Dispatch(args, e)
	case "guest":
		code, err = guest.Dispatch(args, e)
	case "storage":
		code, err = storage.Dispatch(args, e)
	case "info":
		code, err = sysinfo.Run(args, e)
	default:
		err = cli.Usagef("unknown verb group %q (expected: image, layer, container, vm, guest, network, storage, info)", args.Word(0))
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

// helpCmd is *requested* help: exit 0, usage on stdout. usage() below stays on stderr -- it
// accompanies an error, and stdout belongs to the contract.
func helpCmd(e cli.Emit) int {
	e.Result(map[string]any{"ok": true, "command": "help", "usage": usageText}, func() {
		fmt.Print(usageText)
	})
	return cli.OK
}

func versionCmd(e cli.Emit) int {
	e.Result(map[string]any{
		"ok": true, "command": "version",
		"toolVersion": cli.ToolVersion, "contractVersion": cli.ContractVersion,
	}, func() {
		fmt.Printf("hcsctl %s (contract %s)\n", cli.ToolVersion, cli.ContractVersion)
	})
	return cli.OK
}

func usage() {
	fmt.Fprint(os.Stderr, usageText)
}

const usageText = `hcsctl -- a CLI over the Windows Host Compute Service

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
                   [--publish HOST_PORT:CONTAINER_PORT/tcp|udp]...
                   [--acl DIRECTION:ACTION[:tcp|udp]]...
                   [--mount HOST:CONTAINER[:ro]]... [--scratch-size 40GB] [--isolation hyperv|process]
                   [--timeout <dur>] [--label key=value]... [--store <dir>] [--keep]
               Create, boot and run one command in a container (hyperv by default), then tear
               it down. --cmd defaults to "cmd /c ver". --network attaches an endpoint on
               an existing host compute network and reports its address. --publish creates a NAT
               endpoint mapping while the endpoint is created; it exposes the requested host port.
               --mount maps a host
               directory into the guest over VSMB -- not a bind mount, and not Docker
               semantics; both paths drive-letter absolute. ELEVATED.
               --isolation hyperv (default) or process. Process isolation stacks layers on the
               host, needs elevation at every start, and requires an image build inside the
               host's process-isolation compatibility window (see hcsctl info).
               --acl DIRECTION:ACTION[:tcp|udp], repeatable. A create-time endpoint ACL, added
               to the endpoint create document like --publish. Enforced on process isolation +
               NAT and Hyper-V + L2Bridge; refused on every other combination, including
               Hyper-V + NAT where it would be stored without effect. No runtime mutation.
               --timeout bounds the primary command; absent means wait forever.

  container create --ref <ref> [--id <id>] [--cmd "<cmdline>"] [--cpus N] [--memory-mb N]
                   [--hostname H] [--network <name|id>] [--dns-search list]
                   [--publish HOST_PORT:CONTAINER_PORT/tcp|udp]...
                   [--acl DIRECTION:ACTION[:tcp|udp]]...
                   [--mount HOST:CONTAINER[:ro]]... [--scratch-size 40GB] [--isolation hyperv|process]
                   [--store <dir>]
                   [--label key=value]...
               --label stores opaque key=value pairs in state.json, reported by ls and
               inspect and never interpreted -- ownership and run identity are the
               consumer's policy (record an owner pid; scavenge only on proof it is dead).
               --scratch-size grows the scratch VHD so the guest's C: is bigger than the
               default -- anything writing real data wants this. --cmd records the primary
               process; start launches it. Exec the target directly, not via cmd /c -- a
               kill terminates one process, not a tree, and a wrapper's children survive.
               --isolation hyperv (default) or process; process needs elevation at every start
               and a host-compatible image build. Recorded in state.json and reported by inspect.
               --acl DIRECTION:ACTION[:tcp|udp], repeatable. Create-time endpoint ACL; enforced
               on process isolation + NAT and Hyper-V + L2Bridge, refused elsewhere. Recorded in state.json.

  container start  --id <id> | --ref <ref> [--store <dir>]
               With a recorded primary process, start launches it and stays attached as its
               pump, teeing output to primary.log and recording the exit in state.json. The
               pump owns the pipes -- if it dies with its caller, the workload keeps running
               and logs reports the truncation honestly.
  container logs   --id <id> [--follow] [--ref <ref>] [--store <dir>]
               A primary process's retained output, from any invocation -- the file the pump
               wrote, plus status: running, exited (with code), or pump dead. --follow tails
               until the primary exits or the pump dies. Under --stream-json, followed lines
               are framed {"stream":"log"} (the file merges guest stdout and stderr).
  container exec   --id <id> --cmd "<cmdline>" [--cwd D] [--user U] [--env NAME=value]...
                   [--timeout 30s] [--interactive [--tty]] [--ref <ref>] [--store <dir>]
               Default stdin closes immediately. --interactive forwards this process's stdin
               and closes the guest side on EOF; --tty adds an emulated console. Neither can
               be used with --json or --stream-json. Ctrl-C kills only the exec process.

  container kill   --id <id> --pid <pid> [--ref <ref>] [--store <dir>]
               Kill one guest process and confirm it is gone. PIDs come from container ps
               or the exec result. Kill (and --timeout) terminates that process only: a
               cmd /c wrapper's children survive it, so exec the target directly when a
               kill must be total.
  container stop   --id <id> [--force] [--ref <ref>] [--store <dir>]
  container rm     --id <id> [--force] [--ref <ref>] [--store <dir>]
  container ls     [--store <dir>]             Containers and their HCS state.
  container stats   --id <id> [--ref <ref>] [--store <dir>]  Uptime, memory, CPU, storage and network.
  container ps      --id <id> [--ref <ref>] [--store <dir>]  Processes running in the guest.
  container inspect --id <id> [--ref <ref>] [--store <dir>]  What the store and HCS each know.
  container pause   --id <id> [--ref <ref>] [--store <dir>]
  container resume  --id <id> [--ref <ref>] [--store <dir>]

  storage setup-base --layer <dir> [--size-gb N]
               Prepare a base layer for VHD-backed (computestorage) use: blank-base.vhdx and
               blank.vhdx created inside the layer directory. MUTATES the layer -- Hives/ and
               Layout are regenerated -- so point it at a copy, not a store layer. ELEVATED.

  storage mount   --base <dir> --scratch-dir <dir> [--parent <dir>]... [--store <dir>]
  storage mount   --ref <ref> --scratch-dir <dir> [--store <dir>]
               Copy blank.vhdx to sandbox.vhdx (first time), attach it, initialize the
               writable layer and attach the storage filter. Prints the volume carrying the
               merged view. Parents topmost first; defaults to the base. --ref resolves a
               store image's chain instead -- store base layers already carry blank.vhdx
               (wclayer import creates it), so nothing mutates the store. ELEVATED.

  storage unmount --scratch-dir <dir>
               Detach the storage filter and the scratch VHD. ELEVATED.

  storage export  --layer <volume> --dest <existing-dir> [--parent <dir>]... [--writable]
               HcsExportLayer. Works on a *mounted* writable layer's volume path with
               --writable, producing Files/Hives/tombstones. A legacy (wclayer) directory
               layer fails partway; the legacy variants are not public hcsshim.
  storage import  --source <dir> --layer <dest-dir> [--parent <dir>]...
               HcsImportLayer. Not working: fails path-not-found after writing Files
               (issue #18). ELEVATED.

  storage destroy --layer <dir>
               HcsDestroyLayer, verified by directory absence. Layer directories defeat
               ordinary deletion (restored security descriptors); this is the tool that
               removes them. ELEVATED.

  network ls        Host compute networks, their subnets and endpoint counts. Unelevated.
  network endpoints [--network <name|id>]      Endpoints and their addresses. Unelevated.
  network create --name <name> --type nat --subnet <IPv4/CIDR> --gateway <IPv4>
                    Create an explicit NAT network. Does not alter existing networks.
  network create --name <name> --type private
                    Create an isolated private network.
  network rm (--id <guid> | --name <name>)
                    Remove an empty network. Refuses to remove its endpoints.
  network inspect (--id <guid> | --name <name>)
                    The effective HCN document: subnets, routes, MAC pool, DNS, policies,
                    flags, schema version, attached endpoint IDs. Unelevated.

  vm create  --vhdx <path> [--id <guid>] [--cpus N] [--memory-mb N] [--network <name|id|default>] [--dns <IPv4,...>]
             [--serial-pipe \\.\pipe\name] [--no-copy-on-write] [--label key=value]...
             [--store <dir>]
               Make a Hyper-V VM that boots a Gen 2 VHDX. By default the disk is a
               differencing child, so the image is never written to; --no-copy-on-write boots
               the image itself and MUTATES it. The id is a GUID because it is also the VM's
               hvsocket address -- guest info --vmid takes it unchanged. Unelevated;
               Hyper-V Administrators is enough. Does not start it.
               --network default picks the Hyper-V Default Switch, whose DHCP configures an
               arbitrary guest image. NAT and non-Default-Switch ICS networks require --dns and
               are the only networks that accept it;
               vm start programs their HCN allocation in the guest and succeeds only after its
               agent attests the address. The endpoint is deleted by vm rm and nothing else.
               --label stores opaque key=value pairs in state.json, reported by ls and inspect
               and never interpreted -- record an owner pid; scavenge only on proof it is dead.
  vm start   --id <guid> [--store <dir>]
               On NAT and non-Default-Switch ICS networks, success means the guest agent has
               applied and attested static IPv4 networking. Other starts mean firmware running.
  vm stop    --id <guid> [--force] [--store <dir>]
               Without --force, asks the guest through the shutdown integration service; a
               guest that lacks one cannot be asked. --force powers it off.
  vm rm      --id <guid> [--force] [--store <dir>]
               Terminates, then removes only what this tool made. A --no-copy-on-write VM's
               base image is never removed.
  vm ip      --id <guid> [--timeout 60s] [--store <dir>]
               Wait for guest-reported IPv4 addresses and print them. Endpoint allocations are
               used only to identify the guest address, never returned without guest evidence.
  vm netconfig --id <guid> [--dns <ip,ip>] [--interface eth0] [--timeout 45s] [--store <dir>]
               Program the guest's interface with the endpoint's HNS allocation, through the
               agent and the guest's own NetworkManager. For hcsctl-owned networks (NAT),
               which have no DHCP server. The result reports what the interface holds
               afterwards, not what was asked.
  vm ls      [--all] [--store <dir>]           VMs and the state HCS reports for each.
               --all also lists every compute system on the host with its owner, state and
               runtime id -- other tools' VMs included. hcsctl does not scavenge. A consumer
               that does joins three facts: its own --label on a vm, the vm id carried in the
               endpoint's name, and this list.
  vm inspect --id <guid> [--store <dir>]      The store's record plus the HCS properties.
  vm console --id <guid> [--no-input] [--timeout 15s] [--store <dir>]
               Attach to the VM's serial console over its COM1 named pipe. This is the
               break-glass path: no agent, no network adapter, no lease, no firewall rule --
               it works when the agent is what is broken. Input is on by default, so a Linux
               guest with a getty on ttyS0 gives a login prompt; --no-input only watches.
               Nothing is buffered, so a console attached after boot has missed the boot.
               Every VM gets a COM port; --serial-pipe at create time overrides the name.

  guest info --vmid <guid> [--timeout 35s]     What a guest VM says about itself, over a
                                               Hyper-V socket. Needs no NIC, no DHCP lease
                                               and no elevation; needs hcsguest in the image.
  guest exec --vmid <guid> --cmd "..." [--cwd D] [--env NAME=value]... [--timeout 30s]
                                               Run a command in the guest. --timeout must be at
                                               least one second. The guest's exit code is exitCode
                                               in the document, never hcsctl's.
  guest forward --vmid <guid> --port <n> [--listen 127.0.0.1:2222] [--timeout <dur>]
                                               Publish a guest TCP port on the host. The
                                               agent dials it on the guest's loopback, which
                                               the guest firewall does not filter.

  info         [--store <dir>]
               Host build and capability: CimFS support, elevation, Hyper-V Administrators
               membership, privilege state, vmcompute/vmms/hvhost service states, the store,
               and per-image process-isolation compatibility. Unelevated.

global options:
  --json         One JSON document on stdout; progress on stderr.
  --stream-json  With --json: stderr becomes NDJSON, one object per line, so a consumer
                 following a long exec can attribute every line -- {"stream":"progress"} is
                 hcsctl, {"stream":"stdout"|"stderr"} is the guest, per line, live. The final
                 document is unchanged.

exit codes: 0 ok, 1 ran and failed, 64 bad arguments (nothing attempted)
             a guest process's own exit code is reported as exitCode in the result, not as
             hcsctl's exit code
`
