# The base-setup smoke: the operational check behind "works" for storage setup-base --uvm
# (SetupUtilityVMBaseLayer) and storage setup-volume (SetupBaseOSVolume), the last two
# computestorage functions (#18). Windows PowerShell 5.1 compatible.
#
# Both calls MUTATE the layer they are given (Hives\ and layout are regenerated), so this
# works on a backup-mode copy of a store layer, never the store itself. Ordinary copying
# does not reproduce a layer faithfully -- robocopy /B /COPYALL is required.
#
# Two measured requirements this exercises, neither reported by the API as an error:
#   * SetupUtilityVMBaseLayer's uvmPath is <layer>\UtilityVM, NOT UtilityVM\Files
#     (hcsshim documents "the UtilityVM filesystem"; the Files path is ERROR_GEN_FAILURE).
#   * SetupBaseOSVolume silently does nothing on a volume that is not
#     writable-layer-formatted, and fails "file already exists" if the layer already
#     carries Hives\ or layout.
#
#   powershell -NoProfile -File tools\Run-StorageBaseSmoke.ps1 -Ref <store ref>
param(
    [string]$Ref = 'mcr.microsoft.com/windows/nanoserver:ltsc2025',
    [string]$Work = (Join-Path $env:LOCALAPPDATA "hcsctl-smoke\base-$(Get-Date -Format 'yyyyMMdd-HHmmss')")
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

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$null = New-Item -ItemType Directory -Force (Join-Path $repo 'smoke')
Start-Transcript -Path (Join-Path $repo "smoke\base-smoke-$stamp.txt") -Force

"commit: $(git -C $repo rev-parse HEAD 2>$null)"
"ref:    $Ref"
"work:   $Work"
& $bin info --json

$script:passed = 0
$script:failed = 0
function Assert([string]$name, [bool]$cond) {
    if ($cond) { $script:passed++; "  [ OK ] $name" }
    else { $script:failed++; "  [FAIL] $name" }
}

# -- a faithful copy of a materialized store layer ----------------------------------------
"== copy a store layer (backup mode) =="
$lsJson = (& $bin image ls --json 2>$null) | Out-String
$img = ($lsJson | ConvertFrom-Json).images | Where-Object ref -eq $Ref
if ($null -eq $img -or -not $img.materialized) {
    "no materialized layer for $Ref -- run image pull + image import first."
    Stop-Transcript
    exit 1
}
$storeRoot = ($lsJson | ConvertFrom-Json).store
$srcLayer = $img.layers | Select-Object -Last 1   # base layer path if reported
if (-not $srcLayer -or -not (Test-Path $srcLayer)) {
    # image ls reports a layer count, not paths, in some versions: resolve from the store.
    $srcLayer = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'hcsctl\store\layers') -Directory |
        Where-Object { Test-Path (Join-Path $_.FullName 'UtilityVM\Files') } |
        Select-Object -First 1 -ExpandProperty FullName
}
"source layer: $srcLayer"
Assert "source layer carries a UtilityVM" ($null -ne $srcLayer -and (Test-Path (Join-Path $srcLayer 'UtilityVM\Files')))

$layer = Join-Path $Work 'layer'
$null = New-Item -ItemType Directory -Force $Work
robocopy $srcLayer $layer /E /B /COPYALL /DCOPY:DAT /NFL /NDL /NJH /NJS /NP | Out-Null
$srcLicense = (Get-Item (Join-Path $srcLayer 'UtilityVM\Files\License.txt') -ErrorAction SilentlyContinue).Length
$dstLicense = (Get-Item (Join-Path $layer 'UtilityVM\Files\License.txt') -ErrorAction SilentlyContinue).Length
Assert "copy is faithful (file contents, not stubs)" ($srcLicense -gt 0 -and $srcLicense -eq $dstLicense)

# -- setup-base --uvm ---------------------------------------------------------------------
"== storage setup-base --uvm =="
$uvmJson = (& $bin storage setup-base --layer $layer --uvm --size-gb 10 --json 2>$null) | Out-String
Assert "setup-base --uvm exits 0" ($LASTEXITCODE -eq 0)
$uvm = $uvmJson | ConvertFrom-Json
Assert "uvmPath is the UtilityVM directory, not Files" ($uvm.uvmPath -eq (Join-Path $layer 'UtilityVM'))
Assert "SystemTemplateBase.vhdx created" ((Get-Item $uvm.baseVhd -ErrorAction SilentlyContinue).Length -gt 0)
Assert "SystemTemplate.vhdx created" ((Get-Item $uvm.templateVhd -ErrorAction SilentlyContinue).Length -gt 0)

# -- setup-volume: the layer must be unprepared -------------------------------------------
"== storage setup-volume preflight (prepared layer is a usage error) =="
$vhd = Join-Path $Work 'base.vhdx'
$dp = Join-Path $Work 'dp.txt'
"create vdisk file=`"$vhd`" maximum=10240 type=expandable`nattach vdisk`ncreate partition primary`nformat fs=ntfs quick" | Set-Content $dp
diskpart /s $dp | Out-Null
$plainVol = (Get-Disk | Where-Object { $_.Location -eq $vhd } | Get-Partition | Get-Volume).Path
& $bin storage setup-volume --layer $layer --volume $plainVol --json 2>$null | Out-Null
Assert "a layer carrying Hives is exit 64" ($LASTEXITCODE -eq 64)

"== storage setup-volume on a plain NTFS volume is caught as a no-op =="
$fresh = Join-Path $Work 'fresh'
robocopy $layer $fresh /E /B /COPYALL /DCOPY:DAT /NFL /NDL /NJH /NJS /NP | Out-Null
Remove-Item (Join-Path $fresh 'blank-base.vhdx'), (Join-Path $fresh 'blank.vhdx'), (Join-Path $fresh 'layout') -Force -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $fresh 'Hives') -ErrorAction SilentlyContinue
& $bin storage setup-volume --layer $fresh --volume $plainVol --json 2>$null | Out-Null
Assert "a plain NTFS volume is exit 1, not a silent success" ($LASTEXITCODE -eq 1)
"select vdisk file=`"$vhd`"`ndetach vdisk" | Set-Content $dp
diskpart /s $dp | Out-Null

"== storage setup-volume on a writable-layer volume =="
# storage mount produces exactly that volume: sandbox.vhdx attached and initialized.
$scratch = Join-Path $Work 'scratch'
$mountJson = (& $bin storage mount --ref $Ref --scratch-dir $scratch --json 2>$null) | Out-String
Assert "storage mount exits 0" ($LASTEXITCODE -eq 0)
$wlVol = ($mountJson | ConvertFrom-Json).volume
$fresh2 = Join-Path $Work 'fresh2'
robocopy $layer $fresh2 /E /B /COPYALL /DCOPY:DAT /NFL /NDL /NJH /NJS /NP | Out-Null
Remove-Item (Join-Path $fresh2 'blank-base.vhdx'), (Join-Path $fresh2 'blank.vhdx'), (Join-Path $fresh2 'layout') -Force -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $fresh2 'Hives') -ErrorAction SilentlyContinue
& $bin storage setup-volume --layer $fresh2 --volume $wlVol --json 2>$null
Assert "setup-volume exits 0 on a writable-layer volume" ($LASTEXITCODE -eq 0)
# storage mount reports the volume without a trailing backslash; \\?\Volume{...} needs one.
$wlRoot = if ($wlVol.EndsWith('\')) { $wlVol } else { $wlVol + '\' }
Assert "WcSandboxState present on the volume" ([System.IO.Directory]::Exists($wlRoot + 'WcSandboxState'))
Assert "the layer was regenerated (Hives)" (Test-Path (Join-Path $fresh2 'Hives'))
Assert "the layer was regenerated (layout)" (Test-Path (Join-Path $fresh2 'layout'))
& $bin storage unmount --scratch-dir $scratch --json 2>$null | Out-Null
Assert "storage unmount exits 0" ($LASTEXITCODE -eq 0)

""
"passed: $($script:passed)  failed: $($script:failed)"
if ($script:failed -eq 0) { Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue }
else { "work dir retained for inspection: $Work" }
Stop-Transcript
exit ([int]($script:failed -gt 0))
