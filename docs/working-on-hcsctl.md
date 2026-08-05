# Working on hcsctl

For a session starting cold. What is *known* is in [findings.md](findings.md); what is *next* is
in the issues — issue #1 carries the surface inventory, the priority order and the standing
decisions, and does not close.

## Build

```
go build -o hcsctl.exe .
```

Windows only, Go 1.23+. Go is at `C:\Program Files\Go\bin` and is not always on `PATH`.

Reference clones sit beside this repo — read them rather than guessing at an API:
`hcsshim` (the library), `AspireHcs` (the consumer), `hcsspike` (probes), `dcp`.

## The rules

**Public hcsshim packages only** — `pkg/*`, root, `computestorage`, `osversion`. `internal/` is not
importable; needing it means reconsider the design, not fork. Types *aliased* into a public package
(`hcsshim.ContainerConfig` → `internal/hcs/schema1`) are fine — the restriction is on import paths,
not type identity.

**One contract, every verb.** `--json` puts exactly one document on stdout, progress on stderr.
Exit `0` ran, `1` ran and failed, `64` bad arguments with nothing attempted. A *guest* process's
exit code is `exitCode` in the document and never hcsctl's exit code.

**Unknown and duplicate options are errors.** `RejectUnknown` on every verb, so a typo is exit 64
rather than a silently ignored setting. Repeatability is opted into per option.

**Verbs land with something that ran.** A group gets added because it was exercised against a real
host, not because the function exists.

## Smoke testing, which is manual

No CI yet — see issue #3. Most verbs need elevation, so write a transcript script and launch it
elevated:

```powershell
Start-Transcript -Path (Join-Path $PSScriptRoot 'out.txt') -Force
Set-Location 'E:\source\repos\hcs\hcsctl'
& .\hcsctl.exe container run --ref $ref --id smoke1 --store $store
"exit: $LASTEXITCODE"
Stop-Transcript
```

```powershell
Start-Process pwsh -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$script
```

`E:\hcsctl-store` is the working store; importing is slow, so reuse it.
`servercore:ltsc2022` and `dotnet/runtime:8.0-nanoserver-ltsc2022` are already materialized and
both carry a `UtilityVM`. Clean up with `container rm` / `layer unmount`, never `Remove-Item`.

### Three PowerShell traps that have each cost an hour

- **`$LASTEXITCODE` is corrupted by any pipeline.** `& .\hcsctl.exe ... | Select-Object -First 2`
  reports 0 regardless. Redirect to `$null` and check the code on its own line.
- **`$null` binds to a `[string]` P/Invoke parameter as an empty string**, not NULL. If you are
  probing interop, write a single-file C# app (`dotnet run probe.cs`). This produced a confident and
  completely wrong conclusion about CimFS once already.
- **`\\?\Volume{GUID}` paths read as empty** through PowerShell providers. Use .NET file APIs with
  an explicit trailing separator.

## Layout

```
main.go              verb-group dispatch and usage text
internal/cli/        argument parsing, output, exit codes -- the contract lives here
internal/store/      <root>/blobs, /images, /layers, /scratch, /containers
internal/image/      pull, import, ls, rm
internal/layer/      mount, unmount, ls
internal/container/  run, create, start, exec, stop, rm, ls, stats, ps, inspect, pause, resume
internal/network/    ls, endpoints
internal/sysinfo/    info
```

A new verb group is: a package with `Dispatch(*cli.Args, cli.Emit) (int, error)`, a case in
`main.go`, usage text, and a smoke test you actually ran.

One non-obvious implementation note: **drain stdout and stderr concurrently**. Reading them in
sequence deadlocks as soon as the guest fills the pipe you are not reading.
