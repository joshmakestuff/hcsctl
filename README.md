# hcsctl

A CLI over the Windows Host Compute Service, built on [Microsoft/hcsshim](https://github.com/Microsoft/hcsshim).

The goal is to surface HCS as a tool you can drive from a shell or an agent. Image preparation
works today. Layers, compute systems and networking come next — see the roadmap issue.

```
hcsctl image pull   --ref mcr.microsoft.com/windows/nanoserver:ltsc2022
hcsctl image import --ref mcr.microsoft.com/windows/nanoserver:ltsc2022   # elevated
hcsctl image ls
hcsctl image rm     --ref <ref> [--blobs]                                 # elevated
hcsctl info
```

`--json` puts exactly one document on stdout, progress on stderr. Exit codes: `0` ok, `1` ran
and failed, `64` bad arguments with nothing attempted.

## Two rules

**Public hcsshim packages only** — `pkg/*`, the root package, `computestorage`, `osversion`.
Needing `internal/` is a signal to reconsider the design, not to fork.

**`image import` is elevated, permanently.** Extraction needs `SeBackupPrivilege` +
`SeRestorePrivilege`, both UAC filtering triggers. `ProcessBaseLayer` additionally needs an
enabled `BUILTIN\Administrators` SID — a group check no user-rights assignment satisfies in a
filtered token. `hcsctl info` reports what your token actually holds.

## Build

```
go build -o hcsctl.exe .
```

Windows only. Requires Go 1.23+.
