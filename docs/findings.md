# Findings

Facts established by running something on a real host. These do not change when the code does —
if you find yourself updating this file after a refactor, you are updating the wrong thing.

Anything *suspected* rather than measured belongs in an issue, not here.

Host of record: **Windows 11 Enterprise, build 10.0.26200.8894**, HNS schema 16.0, measured
2026-08-05. Re-measure rather than trust the date.

## Elevation

| operation | needs |
|---|---|
| `image pull` | nothing |
| `image import` | `SeBackup` + `SeRestore` **and** an enabled `BUILTIN\Administrators` SID |
| `CreateScratchLayer`, `ActivateLayer`, `AttachVirtualDisk` | `SeManageVolumePrivilege` |
| `PrepareLayer` | an enabled `BUILTIN\Administrators` SID |
| HNS endpoint/namespace create, attach, delete | **nothing** |
| `hcn.GetGlobals` | elevation — the only HNS call that differs |
| `computestorage.FormatWritableLayerVhd` | elevation — denied from a filtered token even holding `SeManageVolumePrivilege`, so the computestorage scratch path is not a lower-privilege route (probe: `hcsspike/probes/computestorage`) |

Three things that get conflated:

- **`SeManageVolumePrivilege` is grantable and survives UAC filtering.** Assign it to a group that
  is not itself a filtering trigger. It is the privilege behind every `0x80070522` here.
- **`SeBackup`/`SeRestore` are filtering triggers.** Holding them causes filtering; they cannot be
  granted *into* a filtered token.
- **An enabled `BUILTIN\Administrators` SID is a group check, not a privilege.** Nothing in secpol
  substitutes. `PrepareLayer` needs it at *every* container start — which is why process isolation
  can never be unprivileged, and why this tool is Hyper-V-isolated first.

## Hyper-V isolation needs less host-side storage work than process isolation

A xenon does **not** need `ActivateLayer`/`PrepareLayer`/`GetLayerMountPath`. The host runs
`CreateScratchLayer` and hands the scratch plus the read-only layers to a utility VM that stacks
them in the guest. `LayerFolderPath` is the scratch directory; `VolumePath` stays empty.

Proof it is really isolated: `servercore:ltsc2022` reports `10.0.20348.5386` from inside a
`10.0.26200.8894` host. That mismatch is impossible without a separate VM.

## Networking

An endpoint ID in `ContainerConfig.EndpointList` plus `AllowUnqualifiedDNSQuery` is the whole of
it. A xenon on the host's existing NAT network got `172.17.167.218/20`, resolved `microsoft.com`,
and fetched `https://www.microsoft.com` for a 200. ICMP to the gateway fails — the gateway drops
it; HTTPS through the same gateway works.

The namespace / `AddNamespaceEndpoint` machinery in hcsshim's `internal/hcsoci/network.go` is the
**v2** path. On v1, HCS plumbs the endpoint into the utility VM itself.

Probes: `hcsspike/probes/hcn/`.

## CimFS

Creating and committing a CIM, including per-file security descriptors, is unprivileged. Mounting
needs more than `SeManageVolumePrivilege`.

hcsshim consumes CIM layers **for process-isolated containers only** — `MountWCOWLayers` errors for
hyperv + CIM. A xenon-first tool gets less from CimFS than the API size suggests.

## API behaviour that is not visible from the call site

- **hcsshim does not write `layerchain.json`.** hcsctl does: `null` for a base layer, otherwise the
  full ancestor list topmost-first.
- **Layer directories defeat ordinary file deletion.** Restored security descriptors produce a wall
  of access-denied. Use `DestroyLayer` — and verify by directory absence, because it can return
  success and leave the tree.
- **`Shutdown` and `Terminate` return `ErrVmcomputeOperationPending` on success.** `Wait` is what
  confirms. Use `hcsshim.IsPending`.
- **`DriverInfo{}` is zero-valued deliberately.** `layerPath()` is `filepath.Join(HomeDir, id)`, so
  an empty `HomeDir` makes the id the full path.
- **A created-but-never-started container reports a blank `State`** from `GetContainers`, which is
  not the same as no compute system at all.
- **`Process.Kill` terminates one process, not a tree.** Killing an exec'd `cmd /c ping ...`
  kills `cmd.exe` and orphans the still-running `PING.EXE`; `ProcessList` carries no parent
  pids to chase it with. When a kill must be total, exec the target directly.
- **A killed guest process reports exit code 1067** (`ERROR_PROCESS_ABORTED`) to whoever else
  is waiting on it.
- **`S_FALSE` (1) is a success HRESULT.** `FAILED(hr)` is `hr < 0`.
- **`hcn`'s `HcnCreateTest*` and `HcnGenerateNATNetwork` live in `hcnutils_test.go`** — not
  importable. Carry the template yourself.
- One `ociwclayer.ImportLayerFromTar` call replaced ~82,690 bytes of hand-written C# P/Invoke.
