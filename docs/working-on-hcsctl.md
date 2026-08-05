# Working on hcsctl

Written for a session starting cold — a new context, a parallel session, or a future you.

## Read these first

| file | what it is for |
|---|---|
| [surface.md](surface.md) | the complete hcsshim inventory and what is wired. The definition of "done" for the project |
| [roadmap.md](roadmap.md) | what to do next and why that order |
| [findings.md](findings.md) | what is known by measurement, and — separately — what is only suspected |
| [runhcs.md](runhcs.md) | why the `container` group is written rather than delegated to hcsshim's OCI runtime |

Then the open issues. Issue #1 is the standing statement of intent and does not close.

## Build and run

```
go build -o hcsctl.exe .
```

Windows only, Go 1.23+. Go is at `C:\Program Files\Go\bin` and is not always on `PATH`.

Reference clones live beside this repo — read them rather than guessing at an API:

```
E:\source\repos\hcs\hcsshim    the library this is built on
E:\source\repos\hcs\dcp        Aspire's Developer Control Plane (Go, MIT)
E:\source\repos\hcs\AspireHcs  the consumer
E:\source\repos\hcs\hcsspike   probes and the retired C# spike
```

## The rules

**Public hcsshim packages only** — `pkg/*`, the root package, `computestorage`, `osversion`.
`internal/` is not importable; needing it means reconsider the design, not fork. Note that types
aliased into a public package (`hcsshim.ContainerConfig` → `internal/hcs/schema1`) are fine — the
restriction is on import paths, not type identity.

**One contract, every verb.** `--json` puts exactly one document on stdout with progress on
stderr. Exit `0` ran, `1` ran and failed, `64` bad arguments with nothing attempted. A *guest*
process's exit code is `exitCode` in the document and never hcsctl's exit code.

**Verbs land with something that ran.** A group gets added because it was exercised against a real
host, not because the function exists. If you cannot run it, say so rather than shipping it.

**Unknown options are errors.** `RejectUnknown` on every verb, so a typo is exit 64 rather than a
silently ignored setting. Duplicate options are rejected too — repeatability is opted into per
option, deliberately.

## Testing, which is manual today

There is no CI and that is a choice, not an oversight — see issue #3 for when that changes.

Most verbs need elevation. The pattern used throughout, which survives the parent process not
being elevated and captures everything:

```powershell
Start-Transcript -Path (Join-Path $PSScriptRoot 'out.txt') -Force
Set-Location 'E:\source\repos\hcs\hcsctl'
& .\hcsctl.exe container run --ref $ref --id smoke1 --store $store
"exit: $LASTEXITCODE"
Stop-Transcript
```

launched with:

```powershell
Start-Process pwsh -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$script
```

### Three PowerShell traps that have each cost an hour here

- **`$LASTEXITCODE` is corrupted by any pipeline.** `& .\hcsctl.exe ... | Select-Object -First 2`
  reports 0 regardless. Redirect to `$null` and check the code on its own line.
- **`$null` binds to a `[string]` P/Invoke parameter as an empty string**, not NULL. If you are
  probing interop, write a single-file C# app (`dotnet run probe.cs`) instead. This produced a
  confident and completely wrong conclusion about CimFS once already.
- **`\\?\Volume{GUID}` paths read as empty** through PowerShell providers. Use the .NET file APIs
  with an explicit trailing separator.

### A test store

`E:\hcsctl-store` is the working store. `hcsctl image ls --store E:\hcsctl-store` shows what is
already materialized — importing is slow, so reuse it.

```
mcr.microsoft.com/windows/servercore:ltsc2022             2 layers   has UtilityVM
mcr.microsoft.com/dotnet/runtime:8.0-nanoserver-ltsc2022  6 layers   has UtilityVM
```

Clean up with `hcsctl container rm` and `hcsctl layer unmount`, never `Remove-Item` — layer
directories carry restored security descriptors that defeat ordinary deletion.

## Layout

```
main.go                    verb-group dispatch and usage text
internal/cli/              argument parsing, output, exit codes -- the contract lives here
internal/store/            <root>/blobs, /images, /layers, /scratch, /containers
internal/image/            pull, import, ls, rm
internal/layer/            mount, unmount, ls  (the argon-shaped storage path)
internal/container/        run, create, start, exec, stop, rm, ls, stats, ps, inspect, pause, resume
internal/network/          ls, endpoints
internal/sysinfo/          info
```

Adding a verb group means: a package with `Dispatch(*cli.Args, cli.Emit) (int, error)`, a case in
`main.go`, usage text, and a smoke test you actually ran.

## Things that will bite

- **`DriverInfo{}` is zero-valued on purpose.** `layerPath()` is `filepath.Join(HomeDir, id)`, so
  an empty `HomeDir` makes the id the full path. That is how this store addresses layers.
- **`DestroyLayer` can report success and leave the tree.** Verify the post-condition.
- **`Shutdown` and `Terminate` return `ErrVmcomputeOperationPending` on success.** The operation is
  asynchronous; `Wait` is what confirms it. Use `hcsshim.IsPending`.
- **Drain stdout and stderr concurrently.** Reading them in sequence deadlocks as soon as the guest
  fills the pipe you are not reading.
- **A created-but-never-started container reports a blank `State`** from `GetContainers`, which is
  not the same as having no compute system. `container ls` distinguishes `created` from `absent`.
- **`hcn`'s `HcnCreateTest*` and `HcnGenerateNATNetwork` helpers live in `hcnutils_test.go`** — not
  importable. Carry the template yourself.
