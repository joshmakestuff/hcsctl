# The block-CIM smoke: the operational check behind "works" for the block / merged /
# verified CIM surface. No shipped Windows build supports block CIMs (hcsshim gates at
# 27766/27800, both placeholders) -- this runs on an Insider host, and its first act is
# recording what that host actually reports. Windows PowerShell 5.1 compatible: Insider
# server VMs have no pwsh.
#
# Flow: three single-file block CIMs (topmost carries a tombstone and a merged link) ->
# merge -> merged mount asserting shadowing/tombstone/merged-link -> sealed CIM ->
# verify -> verified mount (pinned hash) -> tamper case. -Device adds a raw-device pass
# via a diskpart-attached VHD.
#
#   powershell -NoProfile -File tools\Run-CimBlockSmoke.ps1
param(
    [string]$Work = (Join-Path $env:LOCALAPPDATA "hcsctl-smoke\cimblock-$(Get-Date -Format 'yyyyMMdd-HHmmss')"),
    [switch]$Device
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
Start-Transcript -Path (Join-Path $repo "smoke\cimblock-smoke-$stamp.txt") -Force

# -- inputs of record: what this host actually reports is the first measurement ----------
"commit: $(git -C $repo rev-parse HEAD 2>$null)"
"work:   $Work"
$infoJson = (& $bin info --json) | Out-String
$infoJson
$caps = $infoJson | ConvertFrom-Json
"build $($caps.build).$($caps.buildRevision): blockCim=$($caps.blockCimSupported) mergedCim=$($caps.mergedCimSupported) verifiedCim=$($caps.verifiedCimSupported)"
if (-not $caps.blockCimSupported) {
    "blockCimSupported=false -- nothing to smoke here; the gate (27766) is not met or lies."
    Stop-Transcript
    exit 1
}

$script:passed = 0
$script:failed = 0
function Assert([string]$name, [bool]$cond) {
    if ($cond) { $script:passed++; "  [ OK ] $name" }
    else { $script:failed++; "  [FAIL] $name" }
}

# -- three layer trees --------------------------------------------------------------------
$cims = Join-Path $Work 'cims'
foreach ($n in 'l1', 'l2', 'l3') { $null = New-Item -ItemType Directory -Force (Join-Path $Work "src\$n") }
# l3 = base: two files, one to be shadowed, one to be tombstoned.
Set-Content "$Work\src\l3\shadowed.txt" 'from-base'
Set-Content "$Work\src\l3\hidden.txt" 'should-vanish'
Set-Content "$Work\src\l3\base-only.txt" 'base'
# l2 = middle: its own file, and the target the merged link points at.
Set-Content "$Work\src\l2\middle.txt" 'middle'
Set-Content "$Work\src\l2\target.txt" 'linked-content'
# l1 = topmost: shadows, tombstones hidden.txt, links link.txt -> target.txt (in l2).
Set-Content "$Work\src\l1\shadowed.txt" 'from-top'

"== create three single-file block CIMs =="
& $bin cim create --dir "$Work\src\l3" --block "$cims\l3.bcim" --consistent --json 2>$null | Out-Null
Assert "l3 (base) create exits 0" ($LASTEXITCODE -eq 0)
& $bin cim create --dir "$Work\src\l2" --block "$cims\l2.bcim" --consistent --json 2>$null | Out-Null
Assert "l2 create exits 0" ($LASTEXITCODE -eq 0)
& $bin cim create --dir "$Work\src\l1" --block "$cims\l1.bcim" --consistent `
    --tombstone 'hidden.txt' --merged-link 'target.txt=link.txt' --json 2>$null | Out-Null
Assert "l1 (top, tombstone + merged-link) create exits 0" ($LASTEXITCODE -eq 0)
Assert "block containers are single files" ((Test-Path "$cims\l1.bcim") -and ((Get-ChildItem $cims).Count -eq 3))

"== cim merge (topmost first) =="
& $bin cim merge --block "$cims\merged.bcim" --source "$cims\l1.bcim" --source "$cims\l2.bcim" --source "$cims\l3.bcim" --json 2>$null | Out-Null
Assert "merge exits 0" ($LASTEXITCODE -eq 0)

"== merged mount =="
$mountJson = (& $bin cim mount --block "$cims\merged.bcim" --source "$cims\l1.bcim" --source "$cims\l2.bcim" --source "$cims\l3.bcim" --json 2>$null) | Out-String
Assert "merged mount exits 0" ($LASTEXITCODE -eq 0)
$vol = ($mountJson | ConvertFrom-Json).volume
Assert "volume presents" ([System.IO.Directory]::Exists($vol))
Assert "topmost shadows base" ([System.IO.File]::ReadAllText("${vol}shadowed.txt").Trim() -eq 'from-top')
Assert "tombstone hides the lower-layer file" (-not [System.IO.File]::Exists("${vol}hidden.txt"))
Assert "unshadowed base content shows through" ([System.IO.File]::ReadAllText("${vol}base-only.txt").Trim() -eq 'base')
Assert "middle layer shows through" ([System.IO.File]::ReadAllText("${vol}middle.txt").Trim() -eq 'middle')
$linkContent = ''
try { $linkContent = [System.IO.File]::ReadAllText("${vol}link.txt").Trim() } catch {}
Assert "merged link resolves across CIMs" ($linkContent -eq 'linked-content')
& $bin cim unmount --block "$cims\merged.bcim" --json 2>$null | Out-Null
Assert "merged unmount by addressing exits 0" ($LASTEXITCODE -eq 0)

# -- verified: seal, read the hash back, pinned mount, tamper ----------------------------
if (-not $caps.verifiedCimSupported) {
    "  [SKIP] verified section: verifiedCimSupported=false on this host"
} else {
    "== cim create --data-integrity, cim verify =="
    $sealJson = (& $bin cim create --dir "$Work\src\l3" --block "$cims\sealed.bcim" --data-integrity --json 2>$null) | Out-String
    Assert "sealed create exits 0" ($LASTEXITCODE -eq 0)
    $rootHash = ($sealJson | ConvertFrom-Json).rootHash
    Assert "create reports a 64-hex root hash" ($rootHash -match '^[0-9a-f]{64}$')
    $verifyJson = (& $bin cim verify --block "$cims\sealed.bcim" --json) | Out-String
    Assert "verify exits 0" ($LASTEXITCODE -eq 0)
    Assert "verify hash matches create's" (($verifyJson | ConvertFrom-Json).rootHash -eq $rootHash)
    "== verify on an unsealed CIM is exit 1 =="
    & $bin cim verify --block "$cims\l1.bcim" --json 2>$null | Out-Null
    Assert "unsealed verify exits 1" ($LASTEXITCODE -eq 1)

    "== verified mount with pinned hash =="
    $vmountJson = (& $bin cim mount --block "$cims\sealed.bcim" --verified --root-hash $rootHash --json 2>$null) | Out-String
    Assert "verified mount exits 0" ($LASTEXITCODE -eq 0)
    $vvol = ($vmountJson | ConvertFrom-Json).volume
    Assert "verified read succeeds" ([System.IO.File]::ReadAllText("${vvol}base-only.txt").Trim() -eq 'base')
    & $bin cim unmount --block "$cims\sealed.bcim" --json 2>$null | Out-Null
    Assert "verified unmount exits 0" ($LASTEXITCODE -eq 0)

    "== tamper: flip a byte in a copy, verified reads must fail =="
    Copy-Item "$cims\sealed.bcim" "$cims\tampered.bcim"
    $fs = [System.IO.File]::Open("$cims\tampered.bcim", 'Open', 'ReadWrite')
    $null = $fs.Seek(-4096, 'End')
    $b = $fs.ReadByte()
    $null = $fs.Seek(-1, 'Current')
    $fs.WriteByte((($b + 1) % 256))
    $fs.Close()
    $tmountJson = (& $bin cim mount --block "$cims\tampered.bcim" --verified --root-hash $rootHash --json 2>$null) | Out-String
    $tcode = $LASTEXITCODE
    if ($tcode -eq 0) {
        # The mount itself may succeed with verification deferred to reads.
        $tvol = ($tmountJson | ConvertFrom-Json).volume
        $readFailed = $false
        try { $null = [System.IO.File]::ReadAllText("${tvol}base-only.txt") } catch { $readFailed = $true }
        Assert "MEASUREMENT: tampered CIM fails at read" $readFailed
        & $bin cim unmount --block "$cims\tampered.bcim" 2>$null | Out-Null
    } else {
        Assert "MEASUREMENT: tampered CIM fails at mount" ($tcode -eq 1)
    }
}

# -- optional raw-device pass -------------------------------------------------------------
if ($Device) {
    "== device-type block CIM via diskpart VHD =="
    $vhd = Join-Path $Work 'dev.vhdx'
    $dp = Join-Path $Work 'dp.txt'
    "create vdisk file=`"$vhd`" maximum=256 type=expandable`nattach vdisk" | Set-Content $dp
    diskpart /s $dp | Out-Null
    $disk = Get-Disk | Where-Object { $_.Location -eq $vhd }
    if ($null -eq $disk) {
        "  [SKIP] device section: could not attach or find the VHD disk"
    } else {
        $phys = "\\.\PhysicalDrive$($disk.Number)"
        "  device: $phys"
        & $bin cim create --dir "$Work\src\l3" --block $phys --name 'dev.cim' --json 2>$null | Out-Null
        Assert "device create exits 0" ($LASTEXITCODE -eq 0)
        $dmountJson = (& $bin cim mount --block $phys --name 'dev.cim' --json 2>$null) | Out-String
        Assert "device mount exits 0" ($LASTEXITCODE -eq 0)
        $dvol = ($dmountJson | ConvertFrom-Json).volume
        Assert "device-CIM content reads" ([System.IO.File]::ReadAllText("${dvol}base-only.txt").Trim() -eq 'base')
        & $bin cim unmount --block $phys --name 'dev.cim' 2>$null | Out-Null
        Assert "device unmount exits 0" ($LASTEXITCODE -eq 0)
        "detach vdisk`nselect vdisk file=`"$vhd`"`ndetach vdisk" | Set-Content $dp
        diskpart /s $dp | Out-Null
    }
}

""
"passed: $($script:passed)  failed: $($script:failed)"
if ($script:failed -eq 0) { Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue }
else { "work dir retained for inspection: $Work" }
Stop-Transcript
exit ([int]($script:failed -gt 0))
