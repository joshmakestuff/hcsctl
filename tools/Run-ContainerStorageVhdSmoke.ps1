# Elevated real-host proof for `container run --isolation process --storage vhd`:
# an argon whose writable layer is a computestorage VHD scratch. The scratch is
# produced the storage surface's way (blank.vhdx copy + InitializeWritableLayer,
# storage.PrepareScratchVHD), then the wclayer stack (ActivateLayer + PrepareLayer +
# GetLayerMountPath) runs over it, then the container boots. This is the measured
# working shape from hcsctl#86 (2026-08-21): the raw storage-mount volume hangs at
# Start; the stacked computestorage scratch boots.
#
#   tools\Run-ContainerStorageVhdSmoke.ps1 -Store <existing-store> -SkipAcquire
param(
    [string]$Store = (Join-Path $env:LOCALAPPDATA "hcsctl-smoke\hcsctl-vhd-smoke-$(Get-Date -Format 'yyyyMMdd-HHmmss')"),
    [string]$Ref = 'mcr.microsoft.com/windows/nanoserver:ltsc2025',
    [switch]$SkipAcquire
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $repo 'hcsctl.exe'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$id = "vhd-smoke-$stamp"
$out = Join-Path $repo "smoke\container-storage-vhd-$stamp.txt"

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "ELEVATED REQUIRED"
}
if (-not (Test-Path $bin)) { throw "no hcsctl.exe -- build it first" }

function Assert([string]$Name, [bool]$Condition) {
    if (-not $Condition) { $script:failed++; throw "ASSERT: $Name" }
    $script:passed++
    "  [ OK ] $Name"
}

"== container --storage vhd smoke $(Get-Date -Format o) ==" | Tee-Object -FilePath $out
"id:     $id" | Tee-Object -Append -FilePath $out
"store:  $Store" | Tee-Object -Append -FilePath $out
$script:passed = 0
$script:failed = 0

if (-not $SkipAcquire) {
    "== acquire ==" | Tee-Object -Append -FilePath $out
    & $bin image pull --ref $Ref 2>&1 | Tee-Object -Append -FilePath $out
    Assert "pull exits 0" ($LASTEXITCODE -eq 0)
}

"== container run --isolation process --storage vhd ==" | Tee-Object -Append -FilePath $out
# PS 5.1: native stderr that is redirected to a file still throws NativeCommandError when
# $ErrorActionPreference is Stop; drop it around the capture and let Assert do the failing.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$errFile = [IO.Path]::GetTempFileName()
$run = (& $bin container run --ref $Ref --isolation process --storage vhd --id $id --cmd 'cmd /c ver' --json 2>$errFile | Out-String)
$ErrorActionPreference = $prevEAP
$err = if (Test-Path $errFile) { Get-Content $errFile -Raw } else { '' }
Remove-Item $errFile -ErrorAction SilentlyContinue
$run | Tee-Object -Append -FilePath $out
if ($err) { $err | Tee-Object -Append -FilePath $out }
Assert "run exits 0" ($LASTEXITCODE -eq 0)
$doc = $run | ConvertFrom-Json
Assert "run reports ok" $doc.ok
Assert "exit code 0" ($doc.exitCode -eq 0)
Assert "guest reports the OS" ($doc.output -match 'Microsoft Windows')

"== writable layer was the computestorage scratch ==" | Tee-Object -Append -FilePath $out
# The container teardown removed the scratch; prove the shape by re-running with --keep
# and checking the scratch dir carries the computestorage product plus no orphaned systems.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$errFile = [IO.Path]::GetTempFileName()
$keep = (& $bin container run --ref $Ref --isolation process --storage vhd --id "$id-keep" --cmd 'cmd /c ver' --keep --json 2>$errFile | Out-String)
$ErrorActionPreference = $prevEAP
Remove-Item $errFile -ErrorAction SilentlyContinue
$keepDoc = $keep | ConvertFrom-Json
Assert "keep run exits 0" ($LASTEXITCODE -eq 0)
Assert "kept" $keepDoc.kept
# The scratch path is reported in state.json (the run verb's own choice of store); read it
# back rather than assume it is under -Store.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$insp = (& $bin container inspect --id "$id-keep" --json 2>$null | Out-String)
$ErrorActionPreference = $prevEAP
$inspDoc = $insp | ConvertFrom-Json
Assert "inspect reports scratch" ($null -ne $inspDoc.state.scratch)
$scratch = $inspDoc.state.scratch
Assert "sandbox.vhdx exists" (Test-Path (Join-Path $scratch 'sandbox.vhdx'))
"scratch: $scratch" | Tee-Object -Append -FilePath $out

"== teardown ==" | Tee-Object -Append -FilePath $out
& $bin container rm --id "$id-keep" --force 2>&1 | Tee-Object -Append -FilePath $out
Assert "rm exits 0" ($LASTEXITCODE -eq 0)
$left = Get-ComputeProcess -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$id*" }
Assert "no orphaned compute systems" ($null -eq $left)

""
"passed: $($script:passed)  failed: $($script:failed)"
if ($script:failed -eq 0) { "DONE log: $out" } else { "FAILED -- work retained for inspection" }
