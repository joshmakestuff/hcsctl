# Contributing

hcsctl is experimental and pre-1.0. There is no support commitment and no compatibility
guarantee between releases; the `--json` documents and exit codes are the contract, and they
change when the design needs it.

## I'm new to opensource

Please assume ignorance instead of malice.

## Issues

Bugs, questions and proposals go in [issues](https://github.com/joshmakestuff/hcsctl/issues).
Include the hcsctl version (`hcsctl version`), the Windows build (`hcsctl info`), whether the
process was elevated, and the exact command with `--json` output when it applies.

## Changes

- Open an issue first for anything beyond a small fix, so the scope is agreed before the work.
- One change per pull request. `go vet ./... && go build ./... && go test ./...` must pass;
  `contract.yml` runs the same on `windows-latest`.
- Comments state what the code does and the HCS/HNS fact it depends on, not how the decision
  was reached. Measured behaviour goes in the issue, not the code.
- Do not copy or vendor `hcsshim` internal packages. hcsctl binds `vmcompute.dll` and uses
  hcsshim's public API only.
- Windows-only. Tests that need Hyper-V, elevation or a real image are not part of `go test`;
  they live under `tools/` as smoke scripts.

## Releases

Tag `vX.Y.Z` on `main`. `release.yml` builds `hcsctl.exe`, both `hcsguest` binaries, verifies
the version stamps, and publishes the assets with `SHA256SUMS`. Host and guest binaries share
a wire protocol; use the same tag for both.

