# Real-host VM networking smoke test. Run elevated:
#   sudo pwsh -NoProfile -File tools\Run-VmNetworkSmoke.ps1 -VHDX '<images>\rocky-10\Virtual Hard Disks\rocky-10.vhdx'
param(
    [Parameter(Mandatory)] [string]$VHDX,
    [string]$Store = 'E:\hcsctl-store',
    [string]$DNS = '1.1.1.1,8.8.8.8',
    [string]$Subnet = '172.31.240.0/24',
    [string]$Gateway = '172.31.240.1',
    [string]$ProbeIP = '1.1.1.1',
    [string]$ProbeName = 'example.com'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $repo 'hcsctl.exe'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$network = "hcsctl-vm-smoke-$stamp"
$id = [guid]::NewGuid().ToString()
$restartId = $id

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run elevated, for example: sudo pwsh -NoProfile -File tools\Run-VmNetworkSmoke.ps1 -VHDX <path>'
}
if (-not (Test-Path -LiteralPath $bin)) { throw "Build hcsctl first: $bin is missing" }
if (-not (Test-Path -LiteralPath $VHDX)) { throw "VHDX does not exist: $VHDX" }

$createdNetwork = $false
$createdVM = $false
try {
    $net = & $bin network create --name $network --type nat --subnet $Subnet --gateway $Gateway --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $net.ok) { throw 'creating disposable NAT network failed' }
    $createdNetwork = $true

    $created = & $bin vm create --id $id --vhdx $VHDX --store $Store --network $network --dns $DNS --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $created.ok) { throw 'vm create failed' }
    if ($created.dns.Count -eq 0) { throw 'vm create did not persist DNS in its result' }
    $createdVM = $true

    $started = & $bin vm start --id $id --store $Store --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $started.ok -or $null -eq $started.network) { throw "static vm start did not report guest network configuration: $($started | ConvertTo-Json -Compress -Depth 8)" }
    if ($started.network.addresses.Count -eq 0) { throw 'vm start lacks guest network attestation' }

    $ip = & $bin vm ip --id $id --store $Store --timeout 20s --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $ip.ok -or $ip.addresses.Count -eq 0) { throw 'vm ip did not return a guest-observed address' }
    $attested = @($started.network.addresses | ForEach-Object address)
    if (@($ip.addresses | Where-Object { $_ -in $attested }).Count -eq 0) { throw 'vm ip address is absent from guest attestation' }

    $info = & $bin guest info --vmid $id --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $info.ok) { throw 'guest info failed after static network configuration' }
    $probeCommand = switch ($info.guest.os) {
        'linux' { "ping -c 1 -W 5 $ProbeIP && getent ahostsv4 $ProbeName" }
        'windows' { "powershell -NoProfile -Command `"if (-not (Test-Connection -Count 1 -Quiet $ProbeIP)) { exit 1 }; Resolve-DnsName -Type A $ProbeName | Out-Null`"" }
        default { throw "no connectivity probe for guest OS $($info.guest.os)" }
    }
    $probe = & $bin guest exec --vmid $id --cmd $probeCommand --timeout 20s --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $probe.ok -or $probe.exitCode -ne 0) { throw "guest IP/DNS connectivity probe failed: $($probe | ConvertTo-Json -Compress)" }

    & $bin vm stop --id $id --store $Store --force | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'vm stop before restart failed' }
    $restarted = & $bin vm start --id $restartId --store $Store --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $restarted.ok -or -not $restarted.recreated -or $null -eq $restarted.network) { throw 'restarted VM did not reapply and attest static networking' }
    $restartIP = & $bin vm ip --id $restartId --store $Store --timeout 20s --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $restartIP.ok -or $restartIP.addresses.Count -eq 0) { throw 'vm ip did not return a guest-observed address after restart' }

    [pscustomobject]@{ ok = $true; id = $id; network = $network; os = $info.guest.os; addresses = $ip.addresses; restartAddresses = $restarted.network.addresses; probe = @{ ip = $ProbeIP; name = $ProbeName } } | ConvertTo-Json -Depth 6
}
finally {
    if ($createdVM) { & $bin vm rm --id $id --store $Store --force | Out-Null }
    if ($createdNetwork) { & $bin network rm --name $network | Out-Null }
}
