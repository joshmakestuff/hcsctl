# Findings

Facts established by running something, and — kept strictly separate — leads that came from
reading. The split matters: several confident-sounding conclusions in this project's history were
wrong, and every one of them came from the second category being written up like the first.

Every measured entry says what host it was measured on. Re-measure rather than trust a stale date.

Host of record unless stated: **Windows 11 Enterprise, build 10.0.26200.8894**, HNS schema 16.0.

---

# Measured

## Elevation

| operation | needs | measured |
|---|---|---|
| `image pull` | nothing | 2026-08-05 |
| `image import` | `SeBackup` + `SeRestore` **and** an enabled `BUILTIN\Administrators` SID | 2026-08-05 |
| `CreateScratchLayer`, `ActivateLayer`, `AttachVirtualDisk` | `SeManageVolumePrivilege` | 2026-08-05 |
| `PrepareLayer` | an enabled `BUILTIN\Administrators` SID | 2026-08-05 |
| `container run` | as above (via `CreateScratchLayer`) | 2026-08-05 |
| HNS endpoint/namespace create, attach, delete | **nothing** | 2026-08-05 |
| `hcn.GetGlobals` | elevation | 2026-08-05 |

Three things worth keeping straight, because they are routinely conflated:

- **`SeManageVolumePrivilege` is grantable and survives UAC filtering.** Assigning it to a group
  that is not itself a filtering trigger gets it into a filtered token. It is the privilege behind
  every `0x80070522` seen in this project.
- **`SeBackupPrivilege` / `SeRestorePrivilege` are UAC filtering triggers.** Holding them causes
  filtering; they cannot be granted *into* a filtered token.
- **An enabled `BUILTIN\Administrators` SID is a group check, not a privilege.** No user-rights
  assignment in secpol substitutes. This is the hard gate, and `PrepareLayer` runs at *every*
  container start — which is why process isolation can never be unprivileged and why this tool is
  Hyper-V-isolated first.

## Hyper-V isolation works, and needs less host-side storage work than process isolation

`servercore:ltsc2022` on a 26200 host reports `10.0.20348.5386` from inside. A build mismatch like
that is only possible because the guest is a separate VM.

A xenon does **not** need `ActivateLayer` / `PrepareLayer` / `GetLayerMountPath`. The host runs
`CreateScratchLayer` and hands the scratch plus the read-only layer directories to a utility VM
that stacks them in the guest. `ContainerConfig.LayerFolderPath` is the scratch directory and
`VolumePath` stays empty.

Also measured: scratch persists across execs; the host filesystem is not visible from inside;
`--cpus` and `--hostname` reach the guest; a 6-layer nanoserver chain boots and the UVM is
correctly located at the base layer rather than the topmost.

## Layer chaining

hcsshim does **not** write `layerchain.json`. hcsctl does: `null` for a base layer, and for every
other layer the full ancestor list topmost-first.

Residual, never constructed: a same-path-different-content file across two layers would be the
definitive precedence test. Stacking was confirmed indirectly — `cmd.exe` from the nanoserver base
and `dotnet.exe` from an upper layer are both present in the merged volume.

## Layer directories cannot be deleted with ordinary file I/O

Restored security descriptors defeat `Remove-Item` and `os.RemoveAll`, producing a wall of
access-denied. Use `DestroyLayer`, and **verify by directory absence** — `DestroyLayer` can return
success and leave the tree behind.

## Networking

An endpoint on the host's existing NAT network, its ID in `ContainerConfig.EndpointList`:

```
endpoint ip: 172.17.167.218/20
ipconfig     172.17.167.218/20, gw 172.17.160.1, DNS 192.168.1.1   [exit 0]
ping gw      100% loss                                              [exit 1]
nslookup     microsoft.com -> 150.171.109.73                        [exit 0]
curl https   http status 200                                        [exit 0]
```

Two fields is the whole of it — `EndpointList` and `AllowUnqualifiedDNSQuery`. The ping failure is
the NAT gateway dropping ICMP; HTTPS through the same gateway succeeds.

The namespace / `AddNamespaceEndpoint` machinery in hcsshim's `internal/hcsoci/network.go` is the
**v2** path. On v1, HCS plumbs the endpoint into the utility VM itself. Namespaces were probed and
work unelevated, but nothing needed one.

Probes: `hcsspike/probes/hcn/`.

## CimFS

An unprivileged user can create and commit a CIM including per-file security descriptors. Mounting
needs more than `SeManageVolumePrivilege` and is satisfied by elevation.

hcsshim consumes CIM layers **for process-isolated containers only** — `MountWCOWLayers` returns an
error for hyperv + CIM.

## hcsshim replaces a great deal of P/Invoke

One `ociwclayer.ImportLayerFromTar` call replaced ~82,690 bytes of hand-written C# P/Invoke.

## Misreadings that cost real time

- `S_FALSE` (1) is a **success** HRESULT. `FAILED(hr)` is `hr < 0`.
- `HcnCreateImage` returning `0x80070003` on every path was PowerShell binding `$null` to a
  `[string]` parameter as an **empty string**. It produced a confident, wholly wrong "CimFS is
  unavailable on this host". See the `powershell-interop-fallback` note — when interop is involved,
  write the probe as a single-file C# app rather than debugging PowerShell.
- `$LASTEXITCODE` is silently corrupted by piping a native command through anything. Every exit
  code in this repo's smoke tests is checked without a pipeline.

---

# Unverified — leads, not constraints

Nothing below has been run. It came from reading source, docs, or binary strings. Treat it as a
starting point for an investigation. **Check the premise before designing against any of it.**

## One NAT network per host

Repeated from memory, never tested on this host. It is the stated reason `network create` is
absent — creating a second NAT network on a machine that already has Docker's could plausibly
break Docker and WSL, which is not worth discovering by accident. But the limit itself is
unconfirmed, and so is the damage.

To settle it, you would need a machine you are willing to break, or a way to snapshot HNS state.

## Aspire, DCP and Windows networking

Very cursory. A shallow read of `microsoft/dcp` (public, MIT, Go; cloned at
`E:\source\repos\hcs\dcp`) plus documentation. **Nobody has run an Aspire app with a container
resource and observed what the runtime actually did.**

The shape that *appeared* to be there: DCP models a container network as a first-class kind
(`ContainerNetworkSpec` with `NetworkName`, `IPv6`, `Mode`, `Persistent`) and may create one per
AppHost session, which would be the isolation boundary between concurrent apps. If that is right,
it would sit awkwardly against the NAT limit above.

Ways this is likely wrong:

- AspireHcs plugs in through the executable / custom-resource model and may never touch DCP's
  container path at all, in which case none of this applies.
- DCP's network handling may be entirely runtime-specific and irrelevant to a non-Docker
  orchestrator.
- The naming and lifetime details came from string literals, which is the weakest possible source.

DCP's container runtimes are a closed map of two CLI orchestrators
(`internal/containers/runtimes/runtime.go`), so a third would be a fork or a PR rather than a
plugin. Both existing ones shell out to a CLI, which is what hcsctl is — noted as an observation,
not a plan.
