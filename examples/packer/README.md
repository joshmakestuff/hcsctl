# Packer examples: bake hcsguest into an image

Two minimal [Packer](https://developer.hashicorp.com/packer) templates that install the
`hcsguest` agent into a guest image, so a VM built from that image answers `hcsctl guest info`
without any manual step inside the guest.

- `rocky-10/` — Rocky Linux 10, Hyper-V ISO build, runs `install/install-hcsguest.sh`.
- `windows-server-2025/` — Windows Server 2025, Hyper-V ISO build, runs `install/Install-HcsGuest.ps1`.

These are **examples, not a supported hcsctl feature**. They validate with `packer validate`;
they are not run in CI. Treat the OS install (ISO, kickstart, answer file) as scaffolding you
replace with your own base-image process — the part worth copying is the agent-install step.

## What they demonstrate

Each build stages the pinned agent binary and the repo's own installer into the guest, then
runs the installer. No install logic is duplicated in the templates: the same script a user
runs by hand is the script the build runs, so there is one place to maintain.

The installer pins and verifies the artifact — `-s`/`-Sha256` checks the checksum and the
installer asserts the binary's own version stamp — registers the service, starts it, and fails
the build if it does not come up. Each build then reboots the guest and re-asserts the service,
proving it is enabled, not just started once.

## Requirements

- Windows host with Hyper-V and the [Packer Hyper-V plugin](https://developer.hashicorp.com/packer/integrations/hashicorp/hyperv)
  (`packer init .` installs it).
- An OS ISO (Rocky 10 DVD, or a Windows Server 2025 ISO).
- The agent binary for the guest OS, from an hcsctl release: `hcsguest-linux-amd64` or
  `hcsguest-windows-amd64.exe`, plus its line from that release's `SHA256SUMS`. **Use the
  release tag that matches your host `hcsctl`** — the host and guest share a wire protocol.

## Run

```sh
cd rocky-10                       # or windows-server-2025
cp example.pkrvars.hcl my.pkrvars.hcl   # then edit paths, password, checksum
packer init .
packer build -var-file=my.pkrvars.hcl .
```

Output is a VHDX under `output/…/Virtual Hard Disks/`.

## Verify host reachability

The build proves the agent runs *inside* the guest. It cannot prove the *host* can reach it:
the Packer build VM is not an HCS compute system. Do that check after booting the image under
HCS (for example through AspireHcs, or `hcsctl vm` if you boot it directly):

```
hcsctl guest info --vmid <guid>
```

## Note on version pinning

There is no `latest`. The examples install a specific local artifact whose checksum you pass in.
The installers can instead download a pinned tag directly
(`install-hcsguest.sh -v <tag>` / `Install-HcsGuest.ps1 -Version <tag>`); swap the two `file`
+ installer provisioners for a single download call if you prefer that.
