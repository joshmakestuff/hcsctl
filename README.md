# hcsctl

A CLI over the Windows Host Compute Service, built on [Microsoft/hcsshim](https://github.com/Microsoft/hcsshim).

The goal is to surface **all** of HCS as a tool you can drive from a shell or an agent. Images,
layers, Hyper-V-isolated containers and read-only networking work today; the rest is ordered, not
dropped. Near-term priority comes from what an Aspire integration needs — environment into the
guest, an endpoint address, local file mounts. That sets the *order*, not the scope.

**[Issue #1](https://github.com/joshmakestuff/hcsctl/issues/1)** is the live roadmap: the surface
inventory, the priority order, and the standing decisions. Work in progress lives in the
[issues](https://github.com/joshmakestuff/hcsctl/issues). What is known by measurement is in the
workspace's `docs/findings.md`, beside this repo rather than inside it.

Pull an image and run something in an isolated container:

```
hcsctl image pull   --ref mcr.microsoft.com/windows/servercore:ltsc2022
hcsctl image import --ref mcr.microsoft.com/windows/servercore:ltsc2022   # elevated
hcsctl container run --ref mcr.microsoft.com/windows/servercore:ltsc2022 \
                     --cmd "cmd /c ver"                                   # elevated
```

The full surface:

```
hcsctl image pull    --ref <registry/repo:tag>       # unelevated
hcsctl image import  --ref <ref>                     # elevated
hcsctl image ls
hcsctl image rm      --ref <ref> [--blobs]           # elevated

hcsctl layer mount   --ref <ref> [--id <id>] [--scratch-size 40GB]   # elevated; merged volume path
hcsctl layer unmount --id <id>                       # elevated
hcsctl layer ls

hcsctl container run    --ref <ref> [--cmd "..."] [--env NAME=value]... [--network <name|id>]
                        [--mount HOST:CONTAINER[:ro]]... [--timeout 30s] [--cpus N]
                        [--memory-mb N] [--scratch-size 40GB] [--keep]   # elevated; one-shot
hcsctl container create --ref <ref> [--cmd "..."] [--cpus N] [--memory-mb N] [--hostname H]
                        [--network <name|id>] [--mount ...] [--scratch-size 40GB]
                        [--label key=value]...      # stored + reported, never interpreted
hcsctl container start  --id <id>                    # launches a recorded --cmd and pumps it
hcsctl container logs   --id <id> [--follow]         # its retained output, from any invocation
hcsctl container exec   --id <id> --cmd "..." [--cwd D] [--user U] [--env NAME=value]...
                        [--timeout 30s]
hcsctl container kill   --id <id> --pid <pid>        # one process, not a tree
hcsctl container stop   --id <id> [--force]
hcsctl container rm     --id <id> [--force]
hcsctl container ls
hcsctl container stats   --id <id>                   # uptime, memory, CPU, storage, network
hcsctl container ps      --id <id>                   # processes in the guest
hcsctl container inspect --id <id>                   # what the store and HCS each know
hcsctl container pause   --id <id>
hcsctl container resume  --id <id>

hcsctl storage setup-base --layer <dir> [--size-gb N]        # elevated; the computestorage
hcsctl storage mount      --ref <ref> --scratch-dir <dir>    # (VHD-backed) layer surface;
hcsctl storage unmount    --scratch-dir <dir>                # see `hcsctl help` and issue #18
hcsctl storage export     --layer <volume> --dest <dir> [--writable]
hcsctl storage import     --source <dir> --layer <dir>       # not yet seen working (#18)
hcsctl storage destroy    --layer <dir>

hcsctl network ls                                    # unelevated; read-only today --
hcsctl network endpoints [--network <name|id>]       # the hcn write surface is unbuilt (#15, #17)

hcsctl info                                          # host capability + toolVersion/contractVersion
hcsctl help | version
```

`--json` puts exactly one document on stdout, progress on stderr. Exit codes: `0` ok, `1` ran
and failed, `64` bad arguments with nothing attempted. A guest process's own exit code is
reported as `exitCode` in the result document, never as hcsctl's exit code — those two things
mean different things and conflating them makes `--json` unusable.

## Two rules

**Public hcsshim packages only** — `pkg/*`, the root package, `computestorage`, `osversion`.
Needing `internal/` is a signal to reconsider the design, not to fork.

**`image import` is elevated, permanently.** Extraction needs `SeBackupPrivilege` +
`SeRestorePrivilege`, both UAC filtering triggers. `ProcessBaseLayer` additionally needs an
enabled `BUILTIN\Administrators` SID — a group check no user-rights assignment satisfies in a
filtered token. `hcsctl info` reports what your token actually holds.

## Why Hyper-V isolation first

`container` builds Hyper-V-isolated (xenon) containers. The host creates a scratch layer and
hands it, plus the read-only layer directories, to a utility VM that does the stacking inside
the guest — so there is no `ActivateLayer`/`PrepareLayer` on the host and no host volume path.

Process isolation (argon) is the other shape, and it is not first because `PrepareLayer` runs at
*every* container start and needs an enabled `BUILTIN\Administrators` SID. That makes an
unprivileged argon impossible, not merely awkward. A xenon never touches that path.

Measured on Windows 11 build 26200 with an `ltsc2022` image: the guest reports
`10.0.20348.5386` while the host is `10.0.26200.8894`. A version mismatch like that is only
possible because the guest is a separate VM.

## Build

```
go build -o hcsctl.exe .
```

Windows only. Requires Go 1.26+ (the floor is `go.mod`'s directive; CI builds from it).
