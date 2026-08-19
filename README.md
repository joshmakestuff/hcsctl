# hcsctl
A command-line interface over the Windows Host Compute Service (HCS), built on
[Microsoft/hcsshim](https://github.com/Microsoft/hcsshim).

hcsctl exposes hcsshim's HCS and HCN Go APIs as shell commands:
- container images and layers
- Hyper-V and process-isolated containers
- virtual machines
- a VM guest agent for integration scenarios
- host compute networks

Every command has a `--json` form with a fixed document shape and exit codes, so a program or an agent can drive it as well as a person can.

## Status
Experimental, pre-1.0, Windows only. No support commitment; no compatibility guarantee between releases. Releases are published as pre-releases with `SHA256SUMS`.

## What is in the repo
| Path | Contents |
|---|---|
| `main.go`, `internal/` | The `hcsctl` CLI: command groups `image`, `layer`, `container`, `vm`, `network`, `storage`, `guest`, `info` |
| `cmd/hcsguest/` | `hcsguest`, the in-VM agent (Windows and Linux) that answers `guest` commands and `vm ip`/`vm netconfig` over a Hyper-V socket |
| `install/` | In-guest installer scripts for `hcsguest` |
| `examples/packer/` | Packer templates that build guest VM images with `hcsguest` installed |
| `tools/` | Elevated smoke scripts that need Hyper-V and real images; not part of `go test` |
| `docs/` | Usage, the `--json` contract, elevation and isolation rules |
| `.github/workflows/` | `contract.yml` (vet, build, test on `windows-latest`) and `release.yml` (tagged builds and assets) |

## Get started
Download `hcsctl.exe` from the latest release, or build from source:
```
go build -o hcsctl.exe .
```
Then:
```
hcsctl help
hcsctl info
```
`hcsctl help` is the command inventory. [docs/usage.md](docs/usage.md) covers the `--json` contract, elevation requirements, container isolation modes, the guest agent, and worked examples.

## Documentation
- [docs/usage.md](docs/usage.md) — using hcsctl
- [install/README.md](install/README.md) — installing `hcsguest` in a guest image
- [examples/packer/README.md](examples/packer/README.md) — building guest images
- [CONTRIBUTING.md](CONTRIBUTING.md) — change, test and release process
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities

## License
MIT. See [LICENSE](LICENSE).