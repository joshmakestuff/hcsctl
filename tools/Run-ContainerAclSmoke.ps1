# Elevated real-host proof that a create-time ACL actually blocks a reachable process+NAT
# endpoint (#68). This is the enforcement regression: a positive control proves the published
# port is reachable without an ACL, then the same topology with `--acl in:block:tcp` proves the
# host can no longer reach it. Process isolation is required because Hyper-V + NAT stores ACLs
# without dataplane effect, and the code now refuses that combination rather than report it.
#
#   tools\Run-ContainerAclSmoke.ps1 -Store E:\hcsctl-store -SkipAcquire
#   tools\Run-ContainerAclSmoke.ps1 -Ref mcr.microsoft.com/windows/nanoserver:ltsc2025
param(
    [string]$Store = (Join-Path '<tmp>' "hcsctl-acl-smoke-$(Get-Date -Format 'yyyyMMdd-HHmmss')"),
    # Process isolation needs an image built inside the host's compatibility window (see
    # docs/findings.md). servercore ltsc2025 is used, not nanoserver, because it ships the full
    # PowerShell the guest listener needs. Override for another host build.
    [string]$Ref = 'mcr.microsoft.com/windows/servercore:ltsc2025',
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
$controlID = "acl-control-$stamp"
$blockID = "acl-block-$stamp"
$start = $null
$startOut = Join-Path $repo "smoke\container-acl-start-$stamp.out.txt"
$startErr = Join-Path $repo "smoke\container-acl-start-$stamp.err.txt"
$createdNetwork = $false
$networkName = if ($Network) { $Network } else { "hcsctl-acl-$stamp" }

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
Start-Transcript -Path (Join-Path $repo "smoke\container-acl-$stamp.txt") -Force
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

    # The listener binds 0.0.0.0 and answers with a distinctive body. It stays alive until
    # cleanup, so a host request in the control phase is real dataplane evidence.
    $listenerScript = @'
$l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, 8082)
$l.Start()
while ($true) {
    $c = $l.AcceptTcpClient()
    $s = $c.GetStream()
    $body = 'hcsctl-acl'
    $resp = "HTTP/1.1 200 OK`r`nContent-Length: $($body.Length)`r`n`r`n$body"
    $b = [Text.Encoding]::ASCII.GetBytes($resp)
    $s.Write($b, 0, $b.Length)
    $c.Close()
}
'@
    $listener = 'powershell -NoProfile -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($listenerScript))
    $listenerCheck = 'if (-not (Get-NetTCPConnection -LocalPort 8082 -State Listen -ErrorAction SilentlyContinue)) { exit 1 }'
    $listenerCheckCommand = 'powershell -NoProfile -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($listenerCheck))

    # Phase 1 -- positive control: process+NAT with no ACL is reachable. If this fails, the
    # block assertion in phase 2 would be meaningless, so it is the control that makes the
    # regression trustworthy.
    $controlJson = (& $bin container create --ref $Ref --id $controlID --store $Store --isolation process --network $networkName --publish "$HostPort`:8082/tcp" --cmd $listener --json) | Out-String
    Assert 'control container create exits 0' ($LASTEXITCODE -eq 0)
    $control = $controlJson | ConvertFrom-Json
    Assert 'control create reports process isolation' ($control.isolation -eq 'process')
    $start = Start-Process -FilePath $bin -ArgumentList @('container', 'start', '--id', $controlID, '--store', $Store) -PassThru -WindowStyle Hidden -RedirectStandardOutput $startOut -RedirectStandardError $startErr
    Start-Sleep -Seconds 3
    if ($start.HasExited) {
        throw "control start exited $($start.ExitCode): $((Get-Content $startErr -Raw -ErrorAction SilentlyContinue).Trim())"
    }
    $listenerJson = (& $bin container exec --id $controlID --store $Store --cmd $listenerCheckCommand --json) | Out-String
    Assert 'control guest reports a TCP listener on 8082' ($LASTEXITCODE -eq 0 -and ($listenerJson | ConvertFrom-Json).exitCode -eq 0)
    $response = $null
    for ($i = 0; $i -lt 45 -and $null -eq $response; $i++) {
        $response = Get-PublishedHttpResponse $HostPort
        if ($null -eq $response) { Start-Sleep -Seconds 2 }
    }
    Assert 'control: host loopback reaches the guest without an ACL' ($null -ne $response -and $response -match 'HTTP/1.1 200 OK')
    & $bin container rm --id $controlID --store $Store --force
    Assert 'control rm exits 0' ($LASTEXITCODE -eq 0)
    $start.WaitForExit(30000) | Out-Null

    # Phase 2 -- the enforcement proof: same topology plus `--acl in:block:tcp`. The endpoint is
    # created with the ACL policy, and the host must no longer reach the published port even
    # though the guest listener is up.
    $blockJson = (& $bin container create --ref $Ref --id $blockID --store $Store --isolation process --network $networkName --publish "$HostPort`:8082/tcp" --acl in:block:tcp --cmd $listener --json) | Out-String
    Assert 'block container create exits 0' ($LASTEXITCODE -eq 0)
    $block = $blockJson | ConvertFrom-Json
    Assert 'block create reports its ACL' ($block.acls.Count -eq 1 -and $block.acls[0].direction -eq 'In' -and $block.acls[0].action -eq 'Block' -and $block.acls[0].protocol -eq 'tcp')
    $start = Start-Process -FilePath $bin -ArgumentList @('container', 'start', '--id', $blockID, '--store', $Store) -PassThru -WindowStyle Hidden -RedirectStandardOutput $startOut -RedirectStandardError $startErr
    Start-Sleep -Seconds 3
    if ($start.HasExited) {
        throw "block start exited $($start.ExitCode): $((Get-Content $startErr -Raw -ErrorAction SilentlyContinue).Trim())"
    }
    $listenerJson = (& $bin container exec --id $blockID --store $Store --cmd $listenerCheckCommand --json) | Out-String
    Assert 'block guest reports a TCP listener on 8082' ($LASTEXITCODE -eq 0 -and ($listenerJson | ConvertFrom-Json).exitCode -eq 0)
    $blocked = Get-PublishedHttpResponse $HostPort
    Assert 'ACL blocks host loopback from the guest listener' ($null -eq $blocked)

    & $bin container rm --id $blockID --store $Store --force
    Assert 'block rm exits 0' ($LASTEXITCODE -eq 0)
    $start.WaitForExit(30000) | Out-Null
    $eps = (& $bin network endpoints --network $networkName --json) | Out-String
    Assert 'endpoints are removed by teardown' (-not $eps.Contains("$controlID-ep") -and -not $eps.Contains("$blockID-ep"))
}
finally {
    if ($null -ne $start -and -not $start.HasExited) { $start.WaitForExit(30000) | Out-Null }
    try { & $bin container rm --id $controlID --store $Store --force 2>$null | Out-Null } catch {}
    try { & $bin container rm --id $blockID --store $Store --force 2>$null | Out-Null } catch {}
    if ($createdNetwork) { try { & $bin network rm --name $networkName 2>$null | Out-Null } catch {} }
    Stop-Transcript | Out-Null
}
