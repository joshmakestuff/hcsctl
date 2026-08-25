# Using hcsctl

`hcsctl help` is the command inventory; `hcsctl help --json` gives it as a document. This page
covers what the inventory does not: the output contract, elevation, isolation modes, the guest
agent, and worked examples.

## Output contract

- `--json` puts exactly one JSON document on stdout. Progress goes to stderr.
- `--stream-json` (with `--json`) makes stderr NDJSON, one object per line:
  `{"stream":"progress"}` is hcsctl, `{"stream":"stdout"|"stderr"}` is the guest process, live.
  The final stdout document is unchanged.
- Exit codes: `0` ok, `1` ran and failed, `64` bad arguments with nothing attempted.
- A guest process's own exit code is reported as `exitCode` in the result document, never as
  hcsctl's exit code.

## Elevation

`hcsctl info` reports what the current token holds and which commands it can run. Commands
that need elevation say so in `hcsctl help`; nothing escalates on its own.

- **`image import` and `image export` are elevated.** The computestorage service refuses a
  UAC-filtered token, and the import/export calls run under `SeBackupPrivilege` +
  `SeRestorePrivilege`, both removed from a filtered token. (The old wclayer-era
  `BUILTIN\Administrators` group check is gone with wclayer.)
- `image rm`, `layer mount|unmount`, and every `storage` command are elevated.
- **`container create`/`run` are UNELEVATED for both isolations** (measured on a filtered
  medium-IL admin token: scratch production, filter attach, create, run, and teardown all
  succeed). The wclayer-era per-start `BUILTIN\Administrators` gate for process isolation
  is gone entirely -- the modern argon needs no elevation at any point. `--scratch-size`
  needs the grantable `SeManageVolumePrivilege` ("Perform volume maintenance tasks") -- a
  per-user setup step, not elevation.
- `vm` commands are unelevated; membership of Hyper-V Administrators is enough.
- `image pull`, `image ls`, `network ls|endpoints|inspect`, `guest` commands and `info` are
  unelevated.
- **`cim create|merge|usage|verify|destroy` are unelevated** -- building and committing a CIM,
  security descriptors included, needs no privilege (measured). `cim mount|unmount` are
  elevated; the specific right is unidentified -- `SeManageVolumePrivilege` is not sufficient
  (measured).

## Container isolation

`container create` and `container run` build either Hyper-V-isolated (xenon) or
process-isolated (argon) containers. `--isolation hyperv` is the default.

- **hyperv** hands the image layers to a utility VM. The guest can be an older Windows build
  than the host.
- **process** stacks the layers on the host. Every start needs an enabled
  `BUILTIN\Administrators` SID, and the image build must fall inside the host's
  process-isolation compatibility window. `hcsctl info` reports both per image.

## Guest agent

`hcsguest` runs inside a VM as a service and answers `hcsctl guest info|exec|forward` and
`hcsctl vm ip|netconfig` over a Hyper-V socket. The socket needs no NIC, no DHCP lease and no
elevation on the host.

Release assets ship `hcsguest-windows-amd64.exe` and `hcsguest-linux-amd64`;
[`install/`](../install/README.md) has the in-guest installer scripts and
[`examples/packer/`](../examples/packer/README.md) builds images with the agent installed.
Use the same release tag for host and guest: they share the wire protocol.

`vm ip` depends on the agent: it reads the address from the guest, not from the host network
stack. A VM without `hcsguest` reports no address.

## Examples

Pull an image and run a command in a Hyper-V-isolated container:

```
hcsctl image pull   --ref mcr.microsoft.com/windows/servercore:ltsc2022
hcsctl image import --ref mcr.microsoft.com/windows/servercore:ltsc2022   # elevated
hcsctl container run --ref mcr.microsoft.com/windows/servercore:ltsc2022 \
                     --cmd "cmd /c ver"
```

Run the same under process isolation:

```
hcsctl container run --ref mcr.microsoft.com/windows/servercore:ltsc2025 \
                     --isolation process --cmd "cmd /c ver"              # elevated
```

Publish a TCP or UDP port when creating an endpoint on an HCN NAT network. The mapping is
set when the endpoint is created and cannot be changed at runtime:

```
hcsctl container create --ref mcr.microsoft.com/windows/servercore:ltsc2022 \
                        --network my-nat --publish 39082:8082/tcp
```

Create a VM from a VHDX, start it, and read its address through the guest agent. The VM id is
a GUID because it is also the VM's Hyper-V socket address; `guest` commands take it as `--vmid`.
NAT networks require `--dns`:

```
hcsctl vm create --vhdx C:\images\rocky-10.vhdx --network my-nat --dns 1.1.1.1
hcsctl vm start  --id <guid>
hcsctl vm ip     --id <guid>
hcsctl guest exec --vmid <guid> --cmd "uname -a"
```

Build a CIM from a directory tree (unelevated), mount it (elevated), and clean up. The mount
volume GUID derives deterministically from the CIM path, so `unmount` takes the same
addressing `mount` did -- no need to have kept the volume path:

```
hcsctl cim create  --dir C:\src --cim E:\cims\base.cim
hcsctl cim mount   --cim E:\cims\base.cim                  # elevated; prints \\?\Volume{...}\
hcsctl cim unmount --cim E:\cims\base.cim                  # elevated
hcsctl cim destroy --cim E:\cims\base.cim
```

`cim create --block`, `cim merge`, and `cim verify` operate on block CIMs, which the host must
support (`hcsctl info` reports `blockCimSupported`/`mergedCimSupported`/`verifiedCimSupported`;
no shipped Windows build does yet). A tree with alternate-data-stream payloads fails
`cim create` loudly: the payload cannot be written through public hcsshim `pkg/cimfs`, and
dropping it silently would be worse. Extended attributes are not captured.

Drive it from a program:

```
hcsctl --json container run --ref mcr.microsoft.com/windows/servercore:ltsc2022 --cmd "cmd /c ver"
```

## Build

```
go build -o hcsctl.exe .
go vet ./... && go test ./...
```

Windows only. The Go floor is `go.mod`'s `go` directive; CI builds from it. Tests that need
Hyper-V, elevation or a real image are not part of `go test`; they are the smoke scripts under
`tools/`.
