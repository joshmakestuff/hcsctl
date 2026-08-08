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
it. A xenon on the host's existing NAT network took a lease, resolved `microsoft.com`, and
fetched `https://www.microsoft.com` for a 200. ICMP to the gateway fails — the gateway drops it,
while HTTPS through that same gateway works. A failed ping is not a broken network.

The namespace / `AddNamespaceEndpoint` machinery in hcsshim's `internal/hcsoci/network.go` is the
**v2** path. On v1, HCS plumbs the endpoint into the utility VM itself.

Probes: `hcsspike/probes/hcn/`.

## computestorage

- **wclayer import already produces the computestorage artifacts, so store base layers are
  `storage mount`-able as-is.** A base layer imported via `ociwclayer` carries
  `blank-base.vhdx`/`blank.vhdx` (timestamps prove import created them) — no
  `SetupContainerBaseLayer`, no hives regeneration, source untouched. Observed rather than only
  inferred: `storage mount --ref` over the two-layer servercore chain gave the merged view (base
  plus servercore-only content), with writes landing in the scratch and the store untouched.
- **`HcsExportLayer` reads through the mounted filter.** Exporting a *mounted* writable
  layer's volume path with `IsWritableLayer` works and produces `Files`/`Hives`/`$wcidirs$`
  metadata/`tombstones.txt`. The same call on an unmounted scratch directory or on a legacy
  (wclayer) directory layer fails partway with file-not-found — the legacy-format variants
  (`HcsExportLegacyWritableLayer` et al.) are not wrapped by public hcsshim.
- **`computestorage.DestroyLayer` removes a scratch-dir layer** and the directory is gone
  afterwards — same call-then-verify shape as wclayer's, but here absence was observed.
- The raw computestorage syscalls do not enable privileges for you, unlike `ociwclayer`.

## CimFS

Creating and committing a CIM, including per-file security descriptors, is unprivileged. Mounting
needs more than `SeManageVolumePrivilege`.

hcsshim consumes CIM layers **for process-isolated containers only** — `MountWCOWLayers` errors for
hyperv + CIM. A xenon-first tool gets less from CimFS than the API size suggests.

## Scratch sizing

- **The default scratch gives a guest a 20 GB C:.** Measured: `fsutil volume diskfree c:` in a
  servercore xenon reports 19.9 GB total with a default scratch.
- **Both sizing mechanisms work on a xenon, and they are equivalent.** `ExpandScratchSize` on
  the scratch directory after `CreateScratchLayer`, and `StorageSandboxSize` in the v1
  `ContainerConfig`, each produce a 39.9 GB guest C: from a 40 GB request. Only
  `ExpandScratchSize` covers `layer mount`, where there is no config document.
- **`LayerExists` answers "does the directory exist", nothing more.** It returns true for a
  freshly created empty directory and for a torn layer with no `Files` (probe:
  `hcsspike/probes/layerexists`, unelevated -- it needs no elevation). It cannot detect an
  interrupted import.

## API behaviour that is not visible from the call site

- **hcsshim does not write `layerchain.json`.** Whoever imports a layer has to write it.
- **Layer directories defeat ordinary file deletion.** Restored security descriptors produce a wall
  of access-denied. Use `DestroyLayer` — and verify by directory absence, because it can return
  success and leave the tree.
- **`Shutdown` and `Terminate` return `ErrVmcomputeOperationPending` on success.** `Wait` is what
  confirms. Use `hcsshim.IsPending`.
- **A created-but-never-started container reports a blank `State`** from `GetContainers`, which is
  not the same as no compute system at all.
- **`Process.Kill` terminates one process, not a tree.** Killing an exec'd `cmd /c ping ...`
  kills `cmd.exe` and orphans the still-running `PING.EXE`; `ProcessList` carries no parent
  pids to chase it with. When a kill must be total, exec the target directly.
- **A killed guest process reports exit code 1067** (`ERROR_PROCESS_ABORTED`) to whoever else
  is waiting on it.
- **`hcn`'s `HcnCreateTest*` and `HcnGenerateNATNetwork` live in `hcnutils_test.go`** — not
  importable. Carry the template yourself.

## What public hcsshim does not expose

**There is no public way to create a virtual machine.** The root package's only compute-system
constructor is `CreateContainer(id string, c *ContainerConfig)`, and `ContainerConfig` is schema
1. It cannot express a VHDX boot, a UEFI firmware section, a COM port or an `HvSocket` service
table. Everything that can is in `internal/hcs` and `internal/uvm`; `pkg/` holds `cimfs`,
`ociwclayer`, `ncproxy` and `securitypolicy`, none of which create a compute system. Checked
against v0.14.1, 2026-08-08.

The container path works only because schema 1 is the one thing hcsshim exports. `internal/hcs`
is itself a thin wrapper over `vmcompute.dll`, so the v2 API is reachable by binding that DLL
directly (issue #34).

## Hyper-V sockets

**Almost nothing is registered in-box.** On this host,
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices`
holds two entries, both `VM Session Service`. The Linux VSOCK template GUID
`00000000-facb-11e6-bd58-64006a7986d3` is **not** among them, so a host-side connect to a guest
VSOCK port needs a service registered first — and that key is under HKLM, so writing it is
elevated. Measured unelevated, 2026-08-08. Whether an HCS document's `HvSocket` service table
avoids that registration is issue #37.
