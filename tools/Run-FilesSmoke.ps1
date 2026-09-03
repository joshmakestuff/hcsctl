# Real-host VM bind-mount (SMB) smoke test. Run elevated:
#   sudo pwsh -NoProfile -File tools\Run-FilesSmoke.ps1 -VHDX <path-to-linux-guest.vhdx>
#
# Requires a guest image whose hcsguest answers the mount verb (hcsctl v0.8.0+); an older
# agent fails the mount arm. The guest must have cifs (Linux) available; the Rocky 10 fixture
# ships it. Exercises: files prepare/inspect, vm create/start, files expose (rw+ro), guest
# mount, host<->guest reads/writes, read-only enforcement, guest unmount, files unexpose, and
# files remove. Everything it makes is torn down in finally.
param(
    [Parameter(Mandatory)] [string]$VHDX,
    [string]$Store = (Join-Path $env:LOCALAPPDATA 'hcsctl-smoke'),
    [string]$DNS = '1.1.1.1,8.8.8.8',
    [string]$Subnet = '172.31.241.0/24',
    [string]$Gateway = '172.31.241.1'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $repo 'hcsctl.exe'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$network = "hcsctl-files-smoke-$stamp"
$root = Join-Path $env:TEMP "hcsctl-files-smoke-$stamp"
$srcRW = Join-Path $root 'src-rw'
$srcRO = Join-Path $root 'src-ro'
$shareRoot = Join-Path $root 'root'
$id = [guid]::NewGuid().ToString()

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run elevated, for example: sudo pwsh -NoProfile -File tools\Run-FilesSmoke.ps1 -VHDX <path>'
}
if (-not (Test-Path -LiteralPath $bin)) { throw "Build hcsctl first: $bin is missing" }
if (-not (Test-Path -LiteralPath $VHDX)) { throw "VHDX does not exist: $VHDX" }

function Invoke-Hcsctl {
    param([Parameter(ValueFromRemainingArguments)] [string[]]$Rest)
    $out = & $bin @Rest --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $out.ok) { throw "hcsctl $($Rest -join ' ') failed: $($out | ConvertTo-Json -Compress -Depth 8)" }
    return $out
}

$createdNetwork = $false
$prepared = $false
$createdVM = $false
try {
    New-Item -ItemType Directory -Force $srcRW, (Join-Path $srcRW 'sub'), $srcRO | Out-Null
    Set-Content (Join-Path $srcRW 'host.txt') 'from host, read-write'
    Set-Content (Join-Path $srcRO 'note.txt') 'from host, read-only'

    Invoke-Hcsctl network create --name $network --type nat --subnet $Subnet --gateway $Gateway | Out-Null
    $createdNetwork = $true

    Invoke-Hcsctl files prepare --network $network --root $shareRoot | Out-Null
    $prepared = $true
    $insp = Invoke-Hcsctl files inspect --root $shareRoot
    if (-not $insp.prepared) { throw "files inspect reports not prepared: missing $($insp.missing -join ', ')" }
    if ($insp.networks -notcontains $network) { throw "files inspect does not cover the network $network" }

    Invoke-Hcsctl vm create --id $id --vhdx $VHDX --store $Store --network $network --dns $DNS | Out-Null
    $createdVM = $true
    Invoke-Hcsctl vm start --id $id --store $Store | Out-Null

    $info = Invoke-Hcsctl guest info --vmid $id
    if ($info.guest.os -ne 'linux') { throw "this smoke expects a Linux guest; got $($info.guest.os)" }

    $exRW = Invoke-Hcsctl files expose --vmid $id --name data --source $srcRW --root $shareRoot
    $exRO = Invoke-Hcsctl files expose --vmid $id --name cfg --source $srcRO --ro --root $shareRoot

    $uncRW = "\\$Gateway\$($exRW.share)\$($exRW.relativePath)"
    $uncRO = "\\$Gateway\$($exRO.share)\$($exRO.relativePath)"
    Invoke-Hcsctl guest mount --vmid $id --unc $uncRW --path /mnt/data --credential hcsctl-files | Out-Null
    Invoke-Hcsctl guest mount --vmid $id --unc $uncRO --path /mnt/cfg --credential hcsctl-files --ro | Out-Null

    # Host -> guest read, guest -> host write, read-only refusal.
    $probe = Invoke-Hcsctl guest exec --vmid $id --timeout 30s --cmd 'cat /mnt/data/host.txt && cat /mnt/cfg/note.txt && echo from-guest > /mnt/data/guest.txt && (echo x > /mnt/cfg/x.txt 2>/dev/null && echo RO_WRITE_SUCCEEDED || echo ro-write-refused)'
    if ($probe.exitCode -ne 0) { throw "guest read/write probe failed: $($probe | ConvertTo-Json -Compress)" }
    if ($probe.stdout -match 'RO_WRITE_SUCCEEDED') { throw 'read-only mount accepted a write' }
    if (-not (Test-Path (Join-Path $srcRW 'guest.txt'))) { throw 'guest write did not reach the host source' }

    Invoke-Hcsctl guest unmount --vmid $id --path /mnt/data | Out-Null
    Invoke-Hcsctl guest unmount --vmid $id --path /mnt/cfg | Out-Null

    $ls = Invoke-Hcsctl files ls --root $shareRoot
    if ($ls.exposures.Count -ne 2) { throw "files ls expected 2 exposures, got $($ls.exposures.Count)" }
    Invoke-Hcsctl files unexpose --vmid $id --root $shareRoot | Out-Null
    $lsAfter = Invoke-Hcsctl files ls --root $shareRoot
    if ($lsAfter.exposures.Count -ne 0) { throw 'files unexpose left exposures behind' }

    # The source directories and their content survive unexpose untouched.
    if (-not (Test-Path (Join-Path $srcRW 'host.txt')) -or -not (Test-Path (Join-Path $srcRO 'note.txt'))) {
        throw 'unexpose damaged a source directory'
    }

    [pscustomobject]@{ ok = $true; id = $id; network = $network; root = $shareRoot; exposures = @('data (rw)', 'cfg (ro)'); note = 'host<->guest verified, read-only enforced, sources intact' } | ConvertTo-Json -Depth 6
}
finally {
    if ($createdVM) { & $bin vm rm --id $id --store $Store --force | Out-Null }
    if ($prepared) { & $bin files remove --root $shareRoot --force | Out-Null }
    if ($createdNetwork) { & $bin network rm --name $network | Out-Null }
    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
}
