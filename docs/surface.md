# The hcsshim surface, and where hcsctl is against it

**The goal is to surface all of it.** Not the subset a local dev loop needs — that only sets the
*order*. This file is the complete inventory so that "the whole thing" is a checklist rather than
an aspiration, and so any session can see what is left without re-deriving it.

Status values:

| | meaning |
|---|---|
| **done** | wired to a verb and exercised against a real host |
| **next** | prioritized, see [roadmap.md](roadmap.md) |
| **later** | in scope, not prioritized |
| **out** | deliberately excluded, with a reason |

Counts as of 2026-08-05: **39 of 225 in-scope symbols wired (~17%)**. Regenerate with the commands
at the bottom rather than trusting this number after a hcsshim bump.

---

## Root package — layer and container (34 funcs)

| symbol | status | notes |
|---|---|---|
| `CreateContainer` | done | `container create`/`run`, v1 xenon |
| `OpenContainer` | done | every verb acting on an existing container |
| `GetContainers` | done | `container ls`, `container inspect` |
| `CreateScratchLayer` | done | `layer mount`, `container create` |
| `ActivateLayer` / `PrepareLayer` | done | `layer mount` (argon-shaped path) |
| `UnprepareLayer` / `DeactivateLayer` | done | `layer unmount` |
| `GetLayerMountPath` | done | `layer mount`, `layer ls` |
| `DestroyLayer` | done | `layer unmount`, `image rm`, `container rm` |
| `NameToGuid` | done | `ContainerConfig.Layers` ids |
| `IsPending` / `IsAlreadyStopped` / `IsNotExist` | done | teardown paths |
| `LayerExists` | next | cheaper than statting `Files\` |
| `ExpandScratchSize` | next | Aspire wants a sizeable scratch |
| `ExportLayer` / `NewLayerReader` | next | `image export` |
| `ImportLayer` / `NewLayerWriter` | later | `ociwclayer` covers the tar path already |
| `ConvertToBaseLayer` | later | build a base layer from a directory |
| `ProcessBaseLayer` / `ProcessUtilityVMImage` | later | `ociwclayer` calls these internally |
| `CreateLayer` / `CreateSandboxLayer` / `ExpandSandboxSize` | later | legacy spellings of the Scratch calls |
| `GetSharedBaseImages` | later | what the host already has |
| `IsAccessIsDenied` / `IsNotSupported` / `IsTimeout` / `IsAlreadyClosed` / `IsOperationInvalidState` | later | better error classification |
| `NewGUID` | later | |

## Root package — `Container` and `Process` interfaces (26 methods)

| symbol | status | notes |
|---|---|---|
| `Start` / `Shutdown` / `Terminate` / `WaitTimeout` | done | `start`, `stop`, teardown |
| `Pause` / `Resume` | done | `container pause`/`resume` |
| `Statistics` / `ProcessList` | done | `container stats`/`ps` |
| `CreateProcess` / `Close` | done | `container exec` |
| `Process.Stdio` / `CloseStdin` / `Wait` / `ExitCode` / `Close` | done | `container exec` |
| `Process.Kill` | next | no way to stop a runaway exec today |
| `Process.Pid` | next | needed for any detached-process story |
| `Process.ResizeConsole` | next | with `--tty`, issue #7 |
| `Process.WaitTimeout` | next | an exec can currently hang forever |
| `OpenProcess` | later | reattach to a process by pid |
| `Modify` | later | hot-modify a running system (network add/remove) |
| `MappedVirtualDisks` | later | |
| `HasPendingUpdates` | out | returns a hardcoded `false` in hcsshim |

## `hcn` (56 real funcs + 30 methods; the rest of the file is test helpers)

| symbol | status | notes |
|---|---|---|
| `ListNetworks` / `ListEndpoints` | done | `network ls`, `network endpoints` |
| `GetGlobals` | done | `info`; the one HNS call needing elevation |
| `HostComputeNetwork.CreateEndpoint` | next | issue #5a |
| `HostComputeEndpoint.Delete` | next | issue #5a, teardown |
| `GetNetworkByName` / `GetNetworkByID` | next | resolve `--network` |
| `GetEndpointByID` / `GetEndpointByName` | next | |
| `ListEndpointsOfNetwork` | later | one `ListEndpoints` bucketed is cheaper |
| `HostComputeNetwork.Create` / `Delete` | later | issue #5c, **risky** — see [findings.md](findings.md) |
| `NewNamespace` / `AddNamespaceEndpoint` / `RemoveNamespaceEndpoint` | later | v2 path; v1 xenon does not need it |
| `GetNamespaceByID` / `ListNamespaces` / `GetNamespaceEndpointIds` / `GetNamespaceContainerIds` | later | |
| `ModifyEndpointSettings` / `ModifyNamespaceSettings` / `ModifyNetworkSettings` | later | |
| `ApplyPolicy` / `AddPolicy` / `RemovePolicy` | later | ACLs, NAT rules, port mappings |
| `AddLoadBalancer` / `ListLoadBalancers` / `GetLoadBalancerByID` | later | |
| `AddRoute` / `ListRoutes` / `GetRouteByID` | later | |
| the 18 `*Supported() error` checks | next | feed `info`, issue #4 |
| `GetSupportedFeatures` / `GetCachedSupportedFeatures` | next | issue #4 |
| `*Query` variants, `IsNotFoundError` etc. | later | |
| `SetCurrentThreadCompartmentId` | later | run host code inside a container's compartment |

## `computestorage` (14 funcs) — **none wired**

The modern layer API, parallel to legacy wclayer. hcsctl is on legacy by inheritance, because
that is what `ociwclayer` uses — **not by a decision anyone made.** Settling that is its own task;
see [roadmap.md](roadmap.md).

`SetupBaseOSLayer` · `SetupBaseOSVolume` · `SetupContainerBaseLayer` · `SetupUtilityVMBaseLayer` ·
`InitializeWritableLayer` · `FormatWritableLayerVhd` · `GetLayerVhdMountPath` ·
`AttachLayerStorageFilter` · `DetachLayerStorageFilter` · `AttachOverlayFilter` ·
`DetachOverlayFilter` · `ImportLayer` · `ExportLayer` · `DestroyLayer`

## `pkg/ociwclayer` (2 funcs)

| symbol | status | notes |
|---|---|---|
| `ImportLayerFromTar` | done | `image import`; replaced ~82 KB of C# P/Invoke |
| `ExportLayerToTar` | next | `image export` |

## `pkg/cimfs` (18 funcs + 13 methods) — 2 wired

| symbol | status | notes |
|---|---|---|
| `IsCimFSSupported` / `IsBlockCimSupported` | done | `info` |
| `IsMergedCimSupported` / `IsVerifiedCimSupported` | next | issue #4 |
| `Create` / `CimFsWriter.AddFile` / `Write` / `Close` | later | writing a CIM is unprivileged (measured) |
| `Mount` / `Unmount` | later | mounting needs more than `SeManageVolume` |
| `CreateBlockCIM` / `MergeBlockCIMs` / `MountMergedBlockCIMs` | later | |
| `MountVerifiedBlockCIM` / `GetVerificationInfo` | later | |
| `GetCimUsage` / `DestroyCim` | later | |
| `AddLink` / `AddTombstone` / `AddMergedLink` / `CreateAlternateStream` / `Unlink` | later | |

Caveat that shapes priority: hcsshim consumes CIM layers **for process-isolated containers only**
(`MountWCOWLayers` errors for hyperv + CIM). A xenon-first tool gets less from CimFS than the API
size suggests. Still in scope — just not early.

## `pkg/extractuvm` (1 func)

`MakeUtilityVMCIMFromTar` — **later**. Depends on the CimFS work above.

## `osversion` (4 funcs + 2 methods) — 3 wired

`Get` / `Build` / `BuildRevision` done in `info`. `CheckHostAndContainerCompat` is **next** —
it is exactly the host/guest compatibility answer `info` should be giving (issue #4).

---

## Out of scope, with reasons

| package | why |
|---|---|
| root package HNS v1 (22 funcs: `GetHNSNetworkByID`, `HNSEndpointRequest`, `HotAttachEndpoint`, …) | superseded by `hcn`. Exception: `HotAttachEndpoint`/`HotDetachEndpoint` have no v2 equivalent and may come back for #5a — see [roadmap.md](roadmap.md) |
| `pkg/securitypolicy` (39+35) | confidential computing |
| `pkg/amdsevsnp` | confidential computing |
| `pkg/ncproxy` | network-config proxy for a containerd host |
| `pkg/octtrpc` / `pkg/ctrdtaskapi` / `pkg/annotations` | containerd plumbing |
| `pkg/go-runhcs` (13 methods) | drives a `runhcs.exe` built from `cmd/runhcs`. **This one deserves more than a line** — see [runhcs.md](runhcs.md), because runhcs's container verbs genuinely overlap ours |
| `internal/*` | not importable. Needing it is a signal to reconsider the design, not to fork |

---

## Regenerating the counts

```sh
# in the hcsshim clone
grep -h "^func [A-Z]" *.go | grep -v "^func Test" | sed 's/(.*//;s/^func //' | sort -u | wc -l
grep -h "^func [A-Z]" hcn/*.go | grep -v _test | sed 's/(.*//;s/^func //' | sort -u | wc -l

# in hcsctl -- what we actually call
grep -rhoE "hcsshim\.[A-Za-z]+|hcn\.[A-Za-z]+|ociwclayer\.[A-Za-z]+|cimfs\.[A-Za-z]+|osversion\.[A-Za-z]+|computestorage\.[A-Za-z]+" --include=*.go internal/ main.go | sort -u
```

`hcn/*.go` mixes real API and test helpers in non-`_test.go` files (`HcnCreateTest*`,
`HcnGenerateNATNetwork`, `CreateTestNetwork`), so a raw count there overstates by ~20.
