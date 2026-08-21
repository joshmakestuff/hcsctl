# Elevated real-host proof for the container route surface after hcsctl#86:
#   - the default argon route is v2 (ComputeSystem document, computestorage VHD
#     scratch): `container run --isolation process` with no --storage
#   - --storage vhd on argon is the same v2 route, explicitly
#   - --storage wclayer keeps the schema-1 argon route (CreateScratchLayer)
#   - --network attaches an HNS endpoint (v2: namespace + endpoint, hcsoci's
#     shape) and the address is reported
#   - hyperv stays schema-1; --storage vhd is the ACE-granted computestorage
#     scratch (the #86 xenon shape)
#
#   tools\Run-ContainerStorageVhdSmoke.ps1 -Store <existing-store> -SkipAcquire
param(
    [string]$Store = (Join-Path $env:LOCALAPPDATA "hcsctl-smoke\hcsctl-v2-smoke-$(Get-Date -Format 'yyyyMMdd-HHmmss')"),
    [string]$Ref = 'mcr.microsoft.com/windows/nanoserver:ltsc2025',
    [switch]$SkipAcquire
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $repo 'hcsctl.exe'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$id = "v2-smoke-$stamp"
$out = Join-Path $repo "smoke\container-v2-$stamp.txt"

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

"== container route smoke $(Get-Date -Format o) ==" | Tee-Object -FilePath $out
"id:     $id" | Tee-Object -Append -FilePath $out
"store:  $Store" | Tee-Object -Append -FilePath $out
$script:passed = 0
$script:failed = 0

if (-not $SkipAcquire) {
    "== acquire ==" | Tee-Object -Append -FilePath $out
    & $bin image pull --ref $Ref 2>&1 | Tee-Object -Append -FilePath $out
    Assert "pull exits 0" ($LASTEXITCODE -eq 0)
}

# -- helper: run a container command, capture the JSON document ---------------------------
# PS 5.1: native stderr that is redirected to a file still throws NativeCommandError when
# $ErrorActionPreference is Stop; drop it around the capture and let Assert do the failing.
function Invoke-Run([string]$label, [string[]]$extra) {
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $errFile = [IO.Path]::GetTempFileName()
    $runArgs = @('container', 'run', '--ref', $Ref, '--id', $label, '--cmd', 'cmd /c ver', '--json') + $extra
    $run = (& $bin @runArgs 2>$errFile | Out-String)
    $ErrorActionPreference = $prevEAP
    $err = if (Test-Path $errFile) { Get-Content $errFile -Raw } else { '' }
    Remove-Item $errFile -ErrorAction SilentlyContinue
    $run | Tee-Object -Append -FilePath $out
    if ($err) { $err | Tee-Object -Append -FilePath $out }
    $doc = $run | ConvertFrom-Json
    [pscustomobject]@{ doc = $doc; exit = $LASTEXITCODE }
}

"== 1. argon default route is v2 ==" | Tee-Object -Append -FilePath $out
$r = Invoke-Run "$id-argon" @('--isolation', 'process')
Assert "argon default run exits 0" ($r.exit -eq 0)
Assert "argon reports ok" $r.doc.ok
Assert "argon exit code 0" ($r.doc.exitCode -eq 0)
Assert "argon guest reports the OS" ($r.doc.output -match 'Microsoft Windows')
Assert "argon route is v2" ($r.doc.route -eq 'v2')

"== 2. argon --storage vhd is the same v2 route ==" | Tee-Object -Append -FilePath $out
$r = Invoke-Run "$id-vhd" @('--isolation', 'process', '--storage', 'vhd')
Assert "vhd run exits 0" ($r.exit -eq 0)
Assert "vhd reports ok" $r.doc.ok
Assert "vhd route is v2" ($r.doc.route -eq 'v2')

"== 3. argon --storage wclayer keeps the schema-1 route ==" | Tee-Object -Append -FilePath $out
$r = Invoke-Run "$id-wclayer" @('--isolation', 'process', '--storage', 'wclayer')
Assert "wclayer run exits 0" ($r.exit -eq 0)
Assert "wclayer reports ok" $r.doc.ok
Assert "wclayer route is v1" ($r.doc.route -eq 'v1')

"== 4. writable layer was the computestorage scratch ==" | Tee-Object -Append -FilePath $out
# The container teardown removed the scratch; prove the shape by re-running with --keep
# and checking the scratch dir carries the computestorage product plus no orphaned systems.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$errFile = [IO.Path]::GetTempFileName()
$keep = (& $bin container run --ref $Ref --isolation process --id "$id-keep" --cmd 'cmd /c ver' --keep --json 2>$errFile | Out-String)
$ErrorActionPreference = $prevEAP
Remove-Item $errFile -ErrorAction SilentlyContinue
$keepDoc = $keep | ConvertFrom-Json
Assert "keep run exits 0" ($LASTEXITCODE -eq 0)
Assert "kept" $keepDoc.kept
Assert "keep route is v2" ($keepDoc.route -eq 'v2')
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$insp = (& $bin container inspect --id "$id-keep" --json 2>$null | Out-String)
$ErrorActionPreference = $prevEAP
$inspDoc = $insp | ConvertFrom-Json
Assert "inspect reports scratch" ($null -ne $inspDoc.state.scratch)
$scratch = $inspDoc.state.scratch
Assert "sandbox.vhdx exists" (Test-Path (Join-Path $scratch 'sandbox.vhdx'))
"scratch: $scratch" | Tee-Object -Append -FilePath $out

"== 5. network attach on the v2 route ==" | Tee-Object -Append -FilePath $out
# The temp NAT network is global HNS state: created and removed under try/finally
# so a failed assertion cannot strand it.
$netName = "v2-smoke-$stamp"
try {
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $null = (& $bin network create --name $netName --type nat --subnet 172.31.0.0/20 --gateway 172.31.0.1 --json 2>$null | Out-String)
    $ErrorActionPreference = $prevEAP
    Assert "network create exits 0" ($LASTEXITCODE -eq 0)
    $r = Invoke-Run "$id-net" @('--isolation', 'process', '--network', $netName)
    Assert "network run exits 0" ($r.exit -eq 0)
    Assert "network route is v2" ($r.doc.route -eq 'v2')
    Assert "network address reported" ($null -ne $r.doc.addresses -and @($r.doc.addresses).Count -gt 0)
} finally {
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $null = (& $bin network rm --name $netName --json 2>$null | Out-String)
    $ErrorActionPreference = $prevEAP
    Assert "network rm exits 0" ($LASTEXITCODE -eq 0)
}

"== 6. hyperv stays schema-1 on the computestorage scratch ==" | Tee-Object -Append -FilePath $out
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$errFile = [IO.Path]::GetTempFileName()
$xv = (& $bin container run --ref $Ref --isolation hyperv --storage vhd --id "$id-xenon" --cmd 'cmd /c ver' --json 2>$errFile | Out-String)
$ErrorActionPreference = $prevEAP
$err = if (Test-Path $errFile) { Get-Content $errFile -Raw } else { '' }
Remove-Item $errFile -ErrorAction SilentlyContinue
$xv | Tee-Object -Append -FilePath $out
if ($err) { $err | Tee-Object -Append -FilePath $out }
Assert "xenon run exits 0" ($LASTEXITCODE -eq 0)
$xvDoc = $xv | ConvertFrom-Json
Assert "xenon reports ok" $xvDoc.ok
Assert "xenon exit code 0" ($xvDoc.exitCode -eq 0)
Assert "xenon guest reports the OS" ($xvDoc.output -match 'Microsoft Windows')
Assert "xenon used a utility VM" ($xvDoc.utilityVM -ne '')
Assert "xenon route is v1" ($xvDoc.route -eq 'v1')

"== teardown ==" | Tee-Object -Append -FilePath $out
& $bin container rm --id "$id-keep" --force 2>&1 | Tee-Object -Append -FilePath $out
Assert "rm exits 0" ($LASTEXITCODE -eq 0)
$left = Get-ComputeProcess -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$id*" }
Assert "no orphaned compute systems" ($null -eq $left)
$leftNet = Get-HnsNetwork -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "v2-smoke-*" }
Assert "no orphaned networks" ($null -eq $leftNet)

""
"passed: $($script:passed)  failed: $($script:failed)"
if ($script:failed -eq 0) { "DONE log: $out" } else { "FAILED -- work retained for inspection" }
