# hcsctl

A CLI over the Windows Host Compute Service, built on [Microsoft/hcsshim](https://github.com/Microsoft/hcsshim).

The goal is to surface HCS as a tool you can drive from a shell or an agent. Images, layers and
Hyper-V-isolated containers work today. Networking and CimFS come next — see the roadmap issue.

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

hcsctl layer mount   --ref <ref> [--id <id>]         # elevated; merged volume path
hcsctl layer unmount --id <id>                       # elevated
hcsctl layer ls

hcsctl container run    --ref <ref> [--cmd "..."] [--keep]   # elevated; one-shot
hcsctl container create --ref <ref> [--cpus N] [--memory-mb N] [--hostname H]
hcsctl container start  --id <id>
hcsctl container exec   --id <id> --cmd "..." [--cwd D] [--user U]
hcsctl container stop   --id <id> [--force]
hcsctl container rm     --id <id> [--force]
hcsctl container ls

hcsctl info
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

Windows only. Requires Go 1.23+.
