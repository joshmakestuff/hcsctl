#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the hcsguest agent as a Windows service inside a guest VM.

.DESCRIPTION
    Acquires a selected hcsguest.exe (a local artifact via -Path, or a pinned release tag via
    -Version), verifies its identity and checksum before touching anything, installs it at a
    stable machine-wide path, registers and starts it as a Windows service, and fails with
    actionable output if it does not stay running.

    Safe to rerun for repair or upgrade: a replacement binary is verified before it replaces the
    working one, no duplicate service is ever created, and a failed start rolls back to the
    prior install.

.PARAMETER Path
    Local hcsguest.exe (or a .zip containing it). Exactly one of -Path / -Version.

.PARAMETER Version
    Release tag to download, e.g. v0.4.0. Exactly one of -Path / -Version. There is no "latest":
    use the tag of the host hcsctl.

.PARAMETER Sha256
    Optional SHA-256 for a -Path artifact. The -Version path always verifies against the
    release's SHA256SUMS, so -Sha256 applies to -Path only.

.PARAMETER InstallDir
    Install directory. Default C:\Program Files\hcsguest.

.PARAMETER Token
    Optional GitHub token for the release download (raises the API rate limit; required only if the
    repository is not public). Defaults to GH_TOKEN, then GITHUB_TOKEN.

.EXAMPLE
    ./Install-HcsGuest.ps1 -Path .\hcsguest.exe

.EXAMPLE
    ./Install-HcsGuest.ps1 -Version v0.4.0
#>
[CmdletBinding()]
param(
    [string] $Path,
    [string] $Version,
    [string] $Sha256,
    [string] $InstallDir = 'C:\Program Files\hcsguest',
    [string] $Token = $env:GH_TOKEN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrEmpty($Path) -eq [string]::IsNullOrEmpty($Version)) {
    throw 'Provide exactly one of -Path (local artifact) or -Version (release tag).'
}
if (-not $Token -and $env:GITHUB_TOKEN) { $Token = $env:GITHUB_TOKEN }

$ServiceName = 'hcsguest'
$Asset = 'hcsguest-windows-amd64.exe'
$ReleaseBase = 'https://github.com/joshmakestuff/hcsctl/releases/download'
$Exe = Join-Path $InstallDir 'hcsguest.exe'
$Backup = "$Exe.bak"

function Invoke-Download {
    param([string] $Url, [string] $Out)
    $curlArgs = @('-fsSL', '--retry', '3')
    if ($Token) { $curlArgs += @('-H', "Authorization: Bearer $Token") }
    & curl.exe @curlArgs -o $Out $Url
    if ($LASTEXITCODE -ne 0) {
        throw "Download failed ($LASTEXITCODE): $Url. Check the tag exists and ships hcsguest-windows-amd64.exe; set GH_TOKEN if the download is rate-limited."
    }
}

function Invoke-Rollback {
    if (Test-Path -LiteralPath $Backup) {
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        }
        Move-Item -LiteralPath $Backup -Destination $Exe -Force
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        }
        Write-Host 'rolled back to the prior install.'
    }
}

$staging = Join-Path ([IO.Path]::GetTempPath()) ("hcsguest-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging -Force | Out-Null
try {
    # --- acquire ---
    $candidate = $null
    if ($Path) {
        $item = Get-Item -LiteralPath $Path
        if ($item.Extension -eq '.zip') {
            $unzip = Join-Path $staging 'unzip'
            New-Item -ItemType Directory -Path $unzip -Force | Out-Null
            Expand-Archive -LiteralPath $item.FullName -DestinationPath $unzip
            $candidate = Get-ChildItem -Path $unzip -Filter 'hcsguest*.exe' | Select-Object -First 1
            if (-not $candidate) { throw "No hcsguest*.exe found inside '$($item.FullName)'." }
        }
        else {
            $candidate = Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $staging $Asset) -PassThru
        }
        if ($Sha256) {
            $actual = (Get-FileHash -LiteralPath $candidate.FullName -Algorithm SHA256).Hash
            if ($actual -ne $Sha256.ToUpperInvariant()) {
                throw "SHA-256 mismatch for '$($item.FullName)': expected $($Sha256.ToUpperInvariant()), got $actual."
            }
        }
    }
    else {
        if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
            throw 'curl.exe is required for -Version downloads; use -Path instead.'
        }
        $dest = Join-Path $staging $Asset
        $sums = Join-Path $staging 'SHA256SUMS'
        Invoke-Download -Url "$ReleaseBase/$Version/$Asset" -Out $dest
        Invoke-Download -Url "$ReleaseBase/$Version/SHA256SUMS" -Out $sums

        $expected = Get-Content -LiteralPath $sums |
            Where-Object { $_ -match "(\S+)\s+$([regex]::Escape($Asset))\s*$" } |
            ForEach-Object { $Matches[1] } |
            Select-Object -First 1
        if (-not $expected) { throw "SHA256SUMS does not list '$Asset'." }
        $actual = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
        if ($actual -ne $expected.ToUpperInvariant()) {
            throw "SHA-256 mismatch for '$Asset': expected $($expected.ToUpperInvariant()), got $actual."
        }
        $candidate = Get-Item -LiteralPath $dest
    }

    # --- verify identity: the artifact must report the version we asked for ---
    $report = & $candidate.FullName version
    if ($LASTEXITCODE -ne 0) {
        throw "Candidate '$($candidate.FullName)' does not run (version exited $LASTEXITCODE)."
    }
    Write-Host "artifact: $report"
    if ($Version -and ($report -notmatch [regex]::Escape($Version))) {
        throw "Artifact reports '$report', which does not carry the requested version '$Version'."
    }

    # --- install ---
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
    }

    if (Test-Path -LiteralPath $Exe) {
        Move-Item -LiteralPath $Exe -Destination $Backup -Force
    }
    Move-Item -LiteralPath $candidate.FullName -Destination $Exe -Force

    if (-not $service) {
        # New-Service, NOT sc.exe create. Measured 2026-08-08: `sc.exe create` with a path that
        # has spaces and embedded quotes fails 1639 ERROR_INVALID_COMMAND_LINE, because
        # PowerShell's native argument passing rewrites it. New-Service hands the string straight
        # to the service control manager, with no command line in between.
        New-Service -Name $ServiceName `
            -BinaryPathName "`"$Exe`" serve" `
            -DisplayName 'HCS guest agent' `
            -Description 'Answers hcsctl over a Hyper-V socket. Needs no network.' `
            -StartupType Automatic | Out-Null

        # Restart on failure, forever. The host reads an unreachable agent as "guest not ready",
        # so an agent that gave up would leave a guest that looks permanently unready. reset= 0
        # stops the failure count ever resetting to "healthy".
        & sc.exe failure $ServiceName 'reset=' '0' 'actions=' 'restart/2000/restart/2000/restart/2000' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe failure failed ($LASTEXITCODE)." }
    }

    # --- start and assert it stays running ---
    Start-Service -Name $ServiceName
    $deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Seconds 2
        $svc = Get-Service -Name $ServiceName
    } while ($svc.Status -ne 'Running' -and (Get-Date) -lt $deadline)

    Write-Host "hcsguest service: $($svc.Status), start type $((Get-Service $ServiceName).StartType)"
    if ($svc.Status -ne 'Running') {
        Get-WinEvent -LogName System -MaxEvents 20 -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match $ServiceName } |
            ForEach-Object { Write-Host $_.Message }
        throw 'hcsguest did not reach Running.'
    }

    # Local check only: proves the binary runs and reads this guest's state. Host reachability is
    # a host-side check -- a listener probe inside the guest can never catch a dropped packet.
    & $Exe info | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'hcsguest info failed in the guest.' }
    Write-Host 'hcsguest info: ok'
}
catch {
    Invoke-Rollback
    throw
}
finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    # On success the backup of the previous binary is no longer needed (rollback already restored
    # it on the failure path, so it no longer exists here when that happened).
    if (Test-Path -LiteralPath $Backup) { Remove-Item -LiteralPath $Backup -Force -ErrorAction SilentlyContinue }
}
