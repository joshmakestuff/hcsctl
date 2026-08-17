# Elevated real-host proof for create-time HCN NAT port publishing. The mapping is put in the
# endpoint's original create document, then a long-running guest HTTP listener proves that
# host loopback reaches the container. It is a focused lifecycle gate, separate from
# Run-Smoke.ps1, and can be rerun with any compatible Windows container image.
#
#   tools\Run-ContainerPortPublishSmoke.ps1 -Store <existing-store> -SkipAcquire
#   tools\Run-ContainerPortPublishSmoke.ps1 -Ref mcr.microsoft.com/windows/servercore:ltsc2025
param(
    [string]$Store = (Join-Path $env:LOCALAPPDATA "hcsctl-smoke\hcsctl-publish-smoke-$(Get-Date -Format 'yyyyMMdd-HHmmss')"),
    [string]$Ref = 'mcr.microsoft.com/windows/servercore:ltsc2022',
    # Empty creates a disposable NAT. Supplying a name uses that caller-owned NAT and leaves it.
    [string]$Network = '',
    [string]$Subnet = '172.31.241.0/24',
    [string]$Gateway = '172.31.241.1',
    [ValidateRange(1, 65535)] [int]$HostPort = 39082,
    [switch]$SkipAcquire
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $repo 'hcsctl.exe'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$id = "publish-smoke-$stamp"
$start = $null
$startOut = Join-Path $repo "smoke\container-publish-start-$stamp.out.txt"
$startErr = Join-Path $repo "smoke\container-publish-start-$stamp.err.txt"
$createdNetwork = $false
$networkName = if ($Network) { $Network } else { "hcsctl-publish-$stamp" }

function Assert([string]$Name, [bool]$Condition) {
    if (-not $Condition) { throw "ASSERT: $Name" }
    "  [ OK ] $Name"
}

function Get-PublishedHttpResponse([int]$Port) {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync('127.0.0.1', $Port)
        if (-not $connect.Wait(2000)) { return $null }
        $stream = $client.GetStream()
        $stream.ReadTimeout = 2000
        $request = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n")
        $stream.Write($request, 0, $request.Length)
        $buffer = New-Object byte[] 1024
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -eq 0) { return $null }
        return [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
    } catch { return $null } finally { $client.Dispose() }
}

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Not elevated. Run this script from an elevated PowerShell session.'
}
if (-not (Test-Path $bin)) {
    throw "No hcsctl.exe at $bin -- run go build -o hcsctl.exe . first"
}

$null = New-Item -ItemType Directory -Force (Join-Path $repo 'smoke')
Start-Transcript -Path (Join-Path $repo "smoke\container-publish-$stamp.txt") -Force
try {
    "commit:  $(git -C $repo rev-parse HEAD)"
    "ref:     $Ref"
    "store:   $Store"
    "network: $networkName"
    "publish: $HostPort`:8082/tcp"

    if ($Network) {
        $net = ((& $bin network inspect --name $networkName --json) | Out-String | ConvertFrom-Json).network
    } else {
        $net = (& $bin network create --name $networkName --type nat --subnet $Subnet --gateway $Gateway --json) | Out-String | ConvertFrom-Json
        Assert 'disposable NAT creation exits 0' ($LASTEXITCODE -eq 0 -and $net.ok)
        $createdNetwork = $true
    }
    Assert 'selected network is HCN NAT' ($net.Type -eq 'NAT')

    if (-not $SkipAcquire) {
        & $bin image pull --ref $Ref --store $Store
        Assert 'image pull exits 0' ($LASTEXITCODE -eq 0)
        & $bin image import --ref $Ref --store $Store
        Assert 'image import exits 0' ($LASTEXITCODE -eq 0)
    }

    # This listener binds 0.0.0.0 and responds with a distinctive body. The
    # primary stays alive until cleanup so a successful host request is real dataplane evidence.
    $listenerScript = @'
$l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, 8082)
$l.Start()
while ($true) {
    $c = $l.AcceptTcpClient()
    $s = $c.GetStream()
    $b = [byte[]](72,84,84,80,47,49,46,49,32,50,48,48,32,79,75,13,10,67,111,110,116,101,110,116,45,76,101,110,103,116,104,58,32,49,52,13,10,13,10,104,99,115,99,116,108,45,112,117,98,108,105,115,104)
    $s.Write($b, 0, $b.Length)
    $c.Close()
}
'@
    $listener = 'powershell -NoProfile -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($listenerScript))
    $createJson = (& $bin container create --ref $Ref --id $id --store $Store --network $networkName --publish "$HostPort`:8082/tcp" --cmd $listener --json) | Out-String
    Assert 'container create exits 0' ($LASTEXITCODE -eq 0)
    $created = $createJson | ConvertFrom-Json
    Assert 'create reports its publish mapping' ($created.published.Count -eq 1 -and $created.published[0].protocol -eq 'tcp' -and $created.published[0].hostPort -eq $HostPort -and $created.published[0].containerPort -eq 8082)

    $start = Start-Process -FilePath $bin -ArgumentList @('container', 'start', '--id', $id, '--store', $Store) -PassThru -WindowStyle Hidden -RedirectStandardOutput $startOut -RedirectStandardError $startErr
    Start-Sleep -Seconds 3
    if ($start.HasExited) {
        throw "container start exited $($start.ExitCode): $((Get-Content $startErr -Raw -ErrorAction SilentlyContinue).Trim())"
    }
    $listenerCheck = 'if (-not (Get-NetTCPConnection -LocalPort 8082 -State Listen -ErrorAction SilentlyContinue)) { exit 1 }'
    $listenerCheckCommand = 'powershell -NoProfile -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($listenerCheck))
    $listenerJson = (& $bin container exec --id $id --store $Store --cmd $listenerCheckCommand --json) | Out-String
    Assert 'guest reports a TCP listener on 8082' ($LASTEXITCODE -eq 0 -and ($listenerJson | ConvertFrom-Json).exitCode -eq 0)
    $response = $null
    for ($i = 0; $i -lt 45 -and $null -eq $response; $i++) {
        $response = Get-PublishedHttpResponse $HostPort
        if ($null -eq $response) { Start-Sleep -Seconds 2 }
    }
    Assert 'host loopback receives the guest HTTP response' ($null -ne $response -and $response -match 'HTTP/1.1 200 OK' -and $response -match 'hcsctl-publish')

    & $bin container rm --id $id --store $Store --force
    Assert 'container rm exits 0' ($LASTEXITCODE -eq 0)
    $start.WaitForExit(30000) | Out-Null
    $eps = (& $bin network endpoints --network $networkName --json) | Out-String
    Assert 'endpoint is removed by teardown' (-not $eps.Contains("$id-ep"))
    $client = [Net.Sockets.TcpClient]::new()
    try { $client.Connect('127.0.0.1', $HostPort); $forwardingGone = $false } catch { $forwardingGone = $true } finally { $client.Dispose() }
    Assert 'host port no longer forwards after endpoint removal' $forwardingGone

    $runID = "$id-run"
    $runJson = (& $bin container run --ref $Ref --id $runID --store $Store --network $networkName --publish "$HostPort`:8082/tcp" --cmd 'cmd /c ver' --json) | Out-String
    Assert 'container run exits 0 with publish' ($LASTEXITCODE -eq 0)
    $run = $runJson | ConvertFrom-Json
    Assert 'run reports its publish mapping' ($run.published.Count -eq 1 -and $run.published[0].protocol -eq 'tcp' -and $run.published[0].hostPort -eq $HostPort -and $run.published[0].containerPort -eq 8082)
    $eps = (& $bin network endpoints --network $networkName --json) | Out-String
    Assert 'run teardown removes its endpoint' (-not $eps.Contains("$runID-ep"))
}
finally {
    if ($null -ne $start -and -not $start.HasExited) { $start.WaitForExit(30000) | Out-Null }
    try { & $bin container rm --id $id --store $Store --force 2>$null | Out-Null } catch {}
    if ($createdNetwork) { try { & $bin network rm --name $networkName 2>$null | Out-Null } catch {} }
    Stop-Transcript | Out-Null
}
