# Exercises the paths outside static netconfig. Swap only -VHDX to test Linux or Windows.
param(
    [Parameter(Mandatory)] [string]$VHDX,
    [string]$Store = (Join-Path $env:LOCALAPPDATA 'hcsctl-smoke')
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $repo 'hcsctl.exe'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated' }
if (-not (Test-Path -LiteralPath $bin)) { throw "Build hcsctl first: $bin is missing" }
if (-not (Test-Path -LiteralPath $VHDX)) { throw "VHDX does not exist: $VHDX" }

function Invoke-VMCreateStartIP([string]$network, [bool]$expectIP) {
    $id = [guid]::NewGuid().ToString()
    $made = $false
    try {
        $created = & $bin vm create --id $id --vhdx $VHDX --store $Store --network $network --json | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or -not $created.ok) { throw "vm create on $network failed" }
        $made = $true
        $started = & $bin vm start --id $id --store $Store --json | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or -not $started.ok) { throw "vm start on $network failed: $($started | ConvertTo-Json -Compress -Depth 6)" }
        if ($null -ne $started.network) { throw "vm start on $network incorrectly entered static netconfig mode" }
        $ip = & $bin vm ip --id $id --store $Store --timeout 75s --json | ConvertFrom-Json
        if ($expectIP) {
            if ($LASTEXITCODE -ne 0 -or -not $ip.ok -or $ip.addresses.Count -eq 0) { throw "vm ip on $network did not return a guest DHCP address" }
        } else {
            if ($LASTEXITCODE -eq 0 -or $ip.ok) { throw "vm ip on $network unexpectedly reported an address" }
        }
        [pscustomobject]@{ id = $id; started = $started; ip = $ip }
    }
    finally {
        if ($made) { & $bin vm rm --id $id --store $Store --force | Out-Null }
    }
}

$private = "hcsctl-vm-private-$stamp"
$privateMade = $false
try {
    $dhcp = Invoke-VMCreateStartIP -network 'default' -expectIP $true
    $p = & $bin network create --name $private --type private --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $p.ok) { throw 'creating disposable private network failed' }
    $privateMade = $true
    $isolated = Invoke-VMCreateStartIP -network $private -expectIP $false
    [pscustomobject]@{ ok=$true; dhcpAddresses=$dhcp.ip.addresses; privateVm=$isolated.id } | ConvertTo-Json -Depth 5
}
finally {
    if ($privateMade) { & $bin network rm --name $private | Out-Null }
}
