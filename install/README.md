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

- **Pin the version.** Substitute `v0.7.0` with the tag you are pinning. It must be a release
  that ships the guest binaries (`hcsguest-windows-amd64.exe`, `hcsguest-linux-amd64`,
  `SHA256SUMS`). Use the same tag as the host `hcsctl`: the guest agent and
  the host share a wire protocol. There is no `latest` form.
- **Both forms need network.** The download path reaches github.com. For an air-gapped guest, copy
  the artifact in and run the script with `-Path` / `-p <artifact>` (optionally `-Sha256` / `-s`).
- The scripts verify the artifact's checksum and identity before touching anything, and are safe to
  rerun for repair or upgrade: a failed start rolls back to the prior install.
