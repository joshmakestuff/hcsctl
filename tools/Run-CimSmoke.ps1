# The cim smoke: the operational check behind "works" for the standard/forked CIM surface.
# Builds a source tree with the shapes the walk claims to capture (nested dirs, a hardlink
# pair, a symlink, an empty alternate data stream, a distinctive DACL), then exercises
# create / usage / mount / fork+unlink / unmount-by-addressing / destroy, asserting an
# observable postcondition after each step. Transcript retained under smoke\.
#
# The SDDL comparison is a measurement, not just a gate: descriptor round-trip fidelity
# through a CIM was an open question (read-back failed on 2026-08-05). Whatever this run
# shows belongs in docs/findings.md.
#
# pwsh only: Windows PowerShell 5.1 cannot create an empty alternate stream and mangles
# \\?\ paths, which silently invalidates the tree this smoke builds.
#
#   Start-Process pwsh -Verb RunAs -Wait -ArgumentList '-NoProfile','-File','tools\Run-CimSmoke.ps1'
param(
    [string]$Work = (Join-Path $env:LOCALAPPDATA "hcsctl-smoke\cim-$(Get-Date -Format 'yyyyMMdd-HHmmss')")
)
$ErrorActionPreference = 'Continue'
$repo = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $repo 'hcsctl.exe'

if ($PSVersionTable.PSEdition -ne 'Core') {
    Write-Error "This smoke needs pwsh, not Windows PowerShell."
    exit 64
}
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Not elevated. Run via: Start-Process pwsh -Verb RunAs -Wait -ArgumentList '-NoProfile','-File','$PSCommandPath'"
    exit 64
}
if (-not (Test-Path $bin)) {
    Write-Error "No hcsctl.exe at $bin -- go build -o hcsctl.exe . first"
    exit 64
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$null = New-Item -ItemType Directory -Force (Join-Path $repo 'smoke')
Start-Transcript -Path (Join-Path $repo "smoke\cim-smoke-$stamp.txt") -Force

# -- inputs of record ---------------------------------------------------------------------
"commit: $(git -C $repo rev-parse HEAD 2>$null)"
"work:   $Work"
$info = (& $bin info --json) | Out-String
$info
$caps = $info | ConvertFrom-Json
if (-not $caps.cimfsSupported) {
    "cimfsSupported=false -- this host cannot run the cim smoke at all."
    Stop-Transcript
    exit 1
}

$script:passed = 0
$script:failed = 0
function Assert([string]$name, [bool]$cond) {
    if ($cond) { $script:passed++; "  [ OK ] $name" }
    else { $script:failed++; "  [FAIL] $name" }
}

# -- source tree: every shape the walk claims to capture ----------------------------------
$src = Join-Path $Work 'src'
$delta = Join-Path $Work 'delta'
$cims = Join-Path $Work 'cims'
# The delta carries sub\ itself: unlinking a nested parent-CIM path needs the parent
# directory present in the fork's own tree (measured; a layer tar does the same).
$null = New-Item -ItemType Directory -Force "$src\sub", "$delta\sub"
Set-Content "$src\a.txt" 'alpha'
Set-Content "$src\sub\b.txt" 'bravo'
Set-Content "$src\acl.txt" 'guarded'
$null = New-Item -ItemType HardLink -Path "$src\link.txt" -Target "$src\a.txt"
$null = New-Item -ItemType SymbolicLink -Path "$src\sym.txt" -Target 'a.txt'
Set-Content -Path "$src\a.txt" -Stream 'marker' -Value $null   # empty ADS; payloads are unwritable (measured)
icacls "$src\acl.txt" /grant 'Guests:(R)' | Out-Null
$srcSddl = (Get-Acl "$src\acl.txt").Sddl
Set-Content "$delta\c.txt" 'charlie'

# PS provider cmdlets (Get-Item, Get-Acl, -Stream) mangle \\?\Volume{...} paths, and a
# junction onto a CIM volume does not resolve (measured) -- but mountvol drive-letter
# assignment works. .NET IO reads the \\?\ form fine.
$driveLetter = 'Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S' | Where-Object { -not (Test-Path "${_}:\") } | Select-Object -First 1
$mnt = "${driveLetter}:"

# -- create (unelevated by contract; this elevated run still proves the sequence) ---------
"== cim create =="
$createJson = (& $bin cim create --dir $src --cim "$cims\base.cim" --json 2>$null) | Out-String
Assert "create exits 0" ($LASTEXITCODE -eq 0)
$create = $createJson | ConvertFrom-Json
Assert "counts match the tree (4 files, 1 dir, 1 link, 1 stream)" (
    $create.files -eq 4 -and $create.directories -eq 1 -and $create.links -eq 1 -and $create.streams -eq 1)
Assert "region files landed next to the cim" ($null -ne (Get-ChildItem $cims -Filter 'region_*'))

"== cim usage =="
$usageJson = (& $bin cim usage --cim "$cims\base.cim" --json) | Out-String
Assert "usage exits 0" ($LASTEXITCODE -eq 0)
Assert "usage is nonzero" (($usageJson | ConvertFrom-Json).usageBytes -gt 0)

# -- mount: content, links, streams, SD measurement ---------------------------------------
"== cim mount (elevated) =="
$mountJson = (& $bin cim mount --cim "$cims\base.cim" --json 2>$null) | Out-String
Assert "mount exits 0" ($LASTEXITCODE -eq 0)
$vol = ($mountJson | ConvertFrom-Json).volume
Assert "volume presents" ([System.IO.Directory]::Exists($vol))
Assert "file content round-trips" ([System.IO.File]::ReadAllText("${vol}a.txt").Trim() -eq 'alpha')
Assert "nested content round-trips" ([System.IO.File]::ReadAllText("${vol}sub\b.txt").Trim() -eq 'bravo')
Assert "hardlink shares content" ([System.IO.File]::ReadAllText("${vol}link.txt").Trim() -eq 'alpha')
mountvol $mnt $vol
$symItem = Get-Item "$mnt\sym.txt" -ErrorAction SilentlyContinue
Assert "symlink survives as a reparse point" ($null -ne $symItem -and $symItem.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint))
Assert "symlink target is a.txt" ($symItem.Target -match 'a\.txt$')
$streams = (Get-Item "$mnt\a.txt" -Stream * -ErrorAction SilentlyContinue).Stream
Assert "empty ADS present" ($streams -contains 'marker')
# The measurement: descriptor fidelity was unconfirmed (2026-08-05 read-back failed).
$mountedSddl = (Get-Acl "$mnt\acl.txt" -ErrorAction SilentlyContinue).Sddl
"  measured: source SDDL:  $srcSddl"
"  measured: mounted SDDL: $mountedSddl"
Assert "MEASUREMENT: DACL SDDL round-trips through the CIM" ($mountedSddl -eq $srcSddl)
mountvol $mnt /D

# -- fork: delta visible, unlink hides, base shows through --------------------------------
"== cim create --fork-of with --unlink =="
& $bin cim create --dir $delta --cim "$cims\child.cim" --fork-of base.cim --unlink 'sub\b.txt' --json 2>$null | Out-Null
Assert "fork create exits 0" ($LASTEXITCODE -eq 0)
$childMountJson = (& $bin cim mount --cim "$cims\child.cim" --json 2>$null) | Out-String
Assert "fork mount exits 0" ($LASTEXITCODE -eq 0)
$childVol = ($childMountJson | ConvertFrom-Json).volume
Assert "delta file present in fork" ([System.IO.File]::Exists("${childVol}c.txt"))
Assert "unlinked path absent in fork" (-not [System.IO.File]::Exists("${childVol}sub\b.txt"))
Assert "base content visible through fork" ([System.IO.File]::ReadAllText("${childVol}a.txt").Trim() -eq 'alpha')

# -- unmount by CIM addressing: the deterministic GUID earns its keep ---------------------
"== cim unmount --cim (derived GUID, no recorded volume) =="
& $bin cim unmount --cim "$cims\child.cim" --json 2>$null | Out-Null
Assert "fork unmount by addressing exits 0" ($LASTEXITCODE -eq 0)
Assert "fork volume gone" (-not [System.IO.Directory]::Exists($childVol))
& $bin cim unmount --cim "$cims\base.cim" --json 2>$null | Out-Null
Assert "base unmount by addressing exits 0" ($LASTEXITCODE -eq 0)
Assert "base volume gone" (-not [System.IO.Directory]::Exists($vol))

# -- destroy: child first (destroying a parent breaks its forks) --------------------------
"== cim destroy =="
Start-Sleep 3   # handles linger briefly after close (hcsshim's own tests wait this out)
& $bin cim destroy --cim "$cims\child.cim" --json 2>$null | Out-Null
Assert "child destroy exits 0" ($LASTEXITCODE -eq 0)
& $bin cim destroy --cim "$cims\base.cim" --json 2>$null | Out-Null
Assert "base destroy exits 0" ($LASTEXITCODE -eq 0)
Assert "no cim artifacts remain" ($null -eq (Get-ChildItem $cims -ErrorAction SilentlyContinue))

# -- ADS payload refusal: the measured limit fails loudly, undo cleans up -----------------
"== cim create refuses an ADS payload =="
Set-Content -Path "$src\a.txt" -Stream 'payload' -Value 'data'
& $bin cim create --dir $src --cim "$cims\refused.cim" --json 2>$null | Out-Null
Assert "ADS payload is exit 1" ($LASTEXITCODE -eq 1)
Assert "undo removed the partial cim" ($null -eq (Get-ChildItem $cims -ErrorAction SilentlyContinue))

# -- summary ------------------------------------------------------------------------------
""
"passed: $($script:passed)  failed: $($script:failed)"
if ($script:failed -eq 0) { Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue }
else { "work dir retained for inspection: $Work" }
Stop-Transcript
exit ([int]($script:failed -gt 0))
