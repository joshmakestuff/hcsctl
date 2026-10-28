# hcsguest installers

Install the `hcsguest` agent inside an existing VM. These scripts only acquire, verify, install
and start the agent; the VM owner supplies the operating system.

## Windows — elevated PowerShell

```powershell
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/joshmakestuff/hcsctl/v0.7.0/install/Install-HcsGuest.ps1'))) -Version v0.7.0
```

## Linux — run as root

```sh
curl -fsSL https://raw.githubusercontent.com/joshmakestuff/hcsctl/v0.7.0/install/install-hcsguest.sh | sh -s -- -v v0.7.0
```

## Notes

### Managed VirtioFS with hcsd

Use an agent build with `virtiofsManaged` capability support; the older pinned
release examples above do not supply it. The Linux guest needs VirtioFS and
Hyper-V PCI support, root mount privileges, and the detached-mount APIs used by
the agent (`fsopen`, `fsmount`, and `move_mount`), plus `statx` unique mount IDs
(`STATX_MNT_ID_UNIQUE`). Load the required kernel modules before starting the agent.

The kernel must expose a nonzero Hyper-V PCI SWIOTLB allocation through
`/sys/bus/vmbus/drivers/hv_pci/swiotlb_base` and `swiotlb_size`. Where required,
add `hv_pci_swiotlb=67108864` to the guest boot command line. The parameter alone
does not establish that an allocation succeeded.

Prepare mount targets beneath trusted, root-owned directories on every boot.
The agent journals boot-scoped ownership in `/run/hcsguest`; it does not persist
mount requests across guest boots. hcsd retains the requested mount intent and
restores it when the targets exist. Restarting hcsd requires a VM stop/start to
restore VirtioFS sharing; restarting only the guest agent cannot restore the
host backend. Pause/resume is supported; saving a VM with VirtioFS exports is not.

### Installation versions and downloads

- **Pin the version.** Substitute `v0.7.0` with the tag you are pinning. It must be a release
  that ships the guest binaries (`hcsguest-windows-amd64.exe`, `hcsguest-linux-amd64`,
  `SHA256SUMS`). Use the same tag as the host `hcsctl`: the guest agent and
  the host share a wire protocol. There is no `latest` form.
- **Both forms need network.** The download path reaches github.com. For an air-gapped guest, copy
  the artifact in and run the script with `-Path` / `-p <artifact>` (optionally `-Sha256` / `-s`).
- The scripts verify the artifact's checksum and identity before touching anything, and are safe to
  rerun for repair or upgrade: a failed start rolls back to the prior install.
