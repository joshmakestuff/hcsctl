# The overlay smoke: the operational check behind "works" for storage attach-overlay /
# detach-overlay, consuming a CIM the cim verbs produced. Windows PowerShell 5.1
# compatible: the target is an Insider server host without pwsh.
#
# Shape mirrors hcsshim's process-isolated CIM mount (internal/layers/wcow_mount.go):
# content under Files\ inside the CIM, the CIM mounted at a volume, UnionFS overlaying
# <cim-volume>\Files onto a writable volume. The writable volume is a fresh NTFS VHDX
# via diskpart plus a WcSandboxState directory -- the one piece of upstream's
# wclayer-activated scratch the filter actually requires.
#
#   powershell -NoProfile -File tools\Run-StorageOverlaySmoke.ps1
param(
    [string]$Work = (Join-Path $env:LOCALAPPDATA "hcsctl-smoke\overlay-$(Get-Date -Format 'yyyyMMdd-HHmmss')")
)
$ErrorActionPreference = 'Continue'
$repo = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $repo 'hcsctl.exe'

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Not elevated."
    exit 64
}
if (-not (Test-Path $bin)) {
    Write-Error "No hcsctl.exe at $bin"
    exit 64
}
if (Test-Path -LiteralPath $Work) {
    Write-Error "-Work already exists: $Work -- the smoke creates and later deletes this tree; pass a path that does not exist."
    exit 64
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$null = New-Item -ItemType Directory -Force (Join-Path $repo 'smoke')
Start-Transcript -Path (Join-Path $repo "smoke\overlay-smoke-$stamp.txt") -Force

"commit: $(git -C $repo rev-parse HEAD 2>$null)"
"work:   $Work"
& $bin info --json

$script:passed = 0
$script:failed = 0
function Assert([string]$name, [bool]$cond) {
    if ($cond) { $script:passed++; "  [ OK ] $name" }
    else { $script:failed++; "  [FAIL] $name" }
}

# -- a CIM layer with content under Files\, hcsshim's convention --------------------------
$null = New-Item -ItemType Directory -Force "$Work\src\Files\sub"
Set-Content "$Work\src\Files\hello.txt" 'from-cim'
Set-Content "$Work\src\Files\sub\deep.txt" 'deep'
"== cim create + mount =="
& $bin cim create --dir "$Work\src" --cim "$Work\cims\layer.cim" --json 2>$null | Out-Null
Assert "cim create exits 0" ($LASTEXITCODE -eq 0)
$cimMount = (& $bin cim mount --cim "$Work\cims\layer.cim" --json 2>$null) | Out-String
Assert "cim mount exits 0" ($LASTEXITCODE -eq 0)
$cimVol = ($cimMount | ConvertFrom-Json).volume

# -- a writable NTFS volume from a fresh VHDX via diskpart --------------------------------
"== scratch volume (diskpart VHDX) =="
$vhd = Join-Path $Work 'scratch.vhdx'
$dp = Join-Path $Work 'dp.txt'
"create vdisk file=`"$vhd`" maximum=256 type=expandable`nattach vdisk`ncreate partition primary`nformat fs=ntfs quick`n" | Set-Content $dp
diskpart /s $dp | Out-Null
$disk = Get-Disk | Where-Object { $_.Location -eq $vhd }
$scratchVol = ($disk | Get-Partition | Get-Volume).Path
"scratch volume: $scratchVol"
Assert "scratch volume presents" ($null -ne $scratchVol -and [System.IO.Directory]::Exists($scratchVol))
# The overlay filter requires WcSandboxState on the writable volume: without it the
# attach is a bare path-not-found.
$null = [System.IO.Directory]::CreateDirectory($scratchVol + 'WcSandboxState')

# -- attach: the union view --------------------------------------------------------------
$attachCode = $null
try {
    "== storage attach-overlay (unionfs) =="
    & $bin storage attach-overlay --volume $scratchVol --layer "${cimVol}Files" --json 2>$null
    $attachCode = $LASTEXITCODE
    Assert "attach-overlay exits 0" ($attachCode -eq 0)
    if ($attachCode -eq 0) {
        Assert "CIM content visible through the scratch volume" ([System.IO.File]::ReadAllText("${scratchVol}hello.txt").Trim() -eq 'from-cim')
        Assert "nested CIM content visible" ([System.IO.File]::ReadAllText("${scratchVol}sub\deep.txt").Trim() -eq 'deep')
        [System.IO.File]::WriteAllText("${scratchVol}write-probe.txt", $stamp)
        Assert "a write lands through the union view" ([System.IO.File]::Exists("${scratchVol}write-probe.txt"))

        "== storage detach-overlay =="
        & $bin storage detach-overlay --volume $scratchVol --json 2>$null | Out-Null
        Assert "detach-overlay exits 0" ($LASTEXITCODE -eq 0)
        Assert "CIM content gone after detach" (-not [System.IO.File]::Exists("${scratchVol}hello.txt"))
        Assert "the write survived in the scratch" ([System.IO.File]::Exists("${scratchVol}write-probe.txt"))
    } else {
        "  [SKIP] union-view assertions: attach failed on this host"
    }
} finally {
    # Unconditional: a terminating error above must not leak the attached VHD, the
    # overlay, or the mounted CIM. On a normal run the overlay is already detached.
    "== teardown =="
    if ($attachCode -eq 0 -and [System.IO.File]::Exists("${scratchVol}hello.txt")) {
        & $bin storage detach-overlay --volume $scratchVol --json 2>$null | Out-Null
        "teardown: detach-overlay -> exit $LASTEXITCODE"
    }
    "select vdisk file=`"$vhd`"`ndetach vdisk" | Set-Content $dp
    diskpart /s $dp | Out-Null
    Assert "scratch vhd detached" ($null -eq (Get-Disk | Where-Object { $_.Location -eq $vhd }))
    & $bin cim unmount --cim "$Work\cims\layer.cim" --json 2>$null | Out-Null
    Assert "cim unmount exits 0" ($LASTEXITCODE -eq 0)
}

""
"passed: $($script:passed)  failed: $($script:failed)"
if ($script:failed -eq 0) {
    Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $Work) {
        "  [FAIL] work dir survived cleanup: $Work -- remove it before re-running with this path"
        $script:failed++
    }
}
else { "work dir retained for inspection: $Work" }
Stop-Transcript
exit ([int]($script:failed -gt 0))
