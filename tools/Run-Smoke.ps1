# The elevated smoke harness (#24): the operational check behind "works", which the contract
# suite deliberately is not. Runs pull/import/layer mount/container run (with an endpoint),
# the #19 failpoint, and cleanup -- asserting observable postconditions after each step and
# retaining a transcript under smoke\ suitable for attaching to a release or issue.
#
# Execution model: a manual release gate. Run it elevated on a Hyper-V-capable host before
# tagging a release, and attach the transcript. It is not CI: hosted runners have no Hyper-V,
# and the green tick means "honours the contract", never "works".
#
#   Start-Process pwsh -Verb RunAs -Wait -ArgumentList '-NoProfile','-File','tools\Run-Smoke.ps1'
#   # or, with Windows sudo enabled:  sudo pwsh -NoProfile -File tools\Run-Smoke.ps1
#
# Default: a fresh, timestamped store under <tmp>, full pull+import (the real gate, ~250 MB network).
# Quick mode against the working store, skipping pull/import and the final image rm:
#   tools\Run-Smoke.ps1 -Store E:\hcsctl-store -SkipAcquire
param(
    [string]$Store = (Join-Path '<tmp>' "hcsctl-smoke-$(Get-Date -Format 'yyyyMMdd-HHmmss')"),
    [string]$Ref = 'mcr.microsoft.com/windows/servercore:ltsc2022',  # multi-layer, carries a UtilityVM
    [string]$Network = 'nat',
    [switch]$SkipAcquire
)
$ErrorActionPreference = 'Continue'
$repo = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $repo 'hcsctl.exe'
$id = 'smoke'

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
Start-Transcript -Path (Join-Path $repo "smoke\smoke-$stamp.txt") -Force

# -- inputs of record: host, binary, image ------------------------------------------------
"commit: $(git -C $repo rev-parse HEAD 2>$null)"
"ref:    $Ref"
"store:  $Store"
& $bin info --json

$script:passed = 0
$script:failed = 0
function Assert([string]$name, [bool]$cond) {
    if ($cond) { $script:passed++; "  [ OK ] $name" }
    else { $script:failed++; "  [FAIL] $name" }
}
# $LASTEXITCODE is corrupted by any pipeline (issue #39), so every hcsctl
# call captures output on its own line and the code is read immediately after.

# -- pull + import ------------------------------------------------------------------------
if (-not $SkipAcquire) {
    "== image pull =="
    & $bin image pull --ref $Ref --store $Store
    Assert "pull exits 0" ($LASTEXITCODE -eq 0)
    "== image import (elevated) =="
    & $bin image import --ref $Ref --store $Store
    Assert "import exits 0" ($LASTEXITCODE -eq 0)
}
$lsJson = (& $bin image ls --store $Store --json) | Out-String
$ls = $lsJson | ConvertFrom-Json
$img = $ls.images | Where-Object ref -eq $Ref
Assert "record present and materialized" ($null -ne $img -and $img.materialized)
Assert "image is multi-layer (ordering is exercised)" ($img.layers -ge 2)

# -- layer mount: merged view, write isolation, clean unmount -----------------------------
"== layer mount =="
$mountJson = (& $bin layer mount --ref $Ref --id $id --store $Store --json 2>$null) | Out-String
Assert "mount exits 0" ($LASTEXITCODE -eq 0)
$mount = $mountJson | ConvertFrom-Json
# \\?\Volume{...} paths read as empty through PS providers -- .NET IO only.
$vol = $mount.volume
Assert "merged view serves base-layer content (Windows\System32)" ([System.IO.Directory]::Exists("$vol\Windows\System32"))
[System.IO.File]::WriteAllText("$vol\smoke-write-probe.txt", $stamp)
Assert "a write lands through the merged view" ([System.IO.File]::Exists("$vol\smoke-write-probe.txt"))
$topLayer = $mount.chain[0]
Assert "the write did not reach the read-only chain" (-not (Test-Path (Join-Path $topLayer 'Files\smoke-write-probe.txt')))
"== layer unmount =="
& $bin layer unmount --id $id --store $Store
Assert "unmount exits 0" ($LASTEXITCODE -eq 0)
Assert "scratch removed by unmount" (-not (Test-Path (Join-Path $Store "scratch\$id")))

# -- container run: guest output, endpoint lifecycle, teardown ----------------------------
"== container run (one-shot, with endpoint) =="
$runJson = (& $bin container run --ref $Ref --id $id --store $Store --network $Network --cmd 'cmd /c ver' --json 2>$null) | Out-String
Assert "run exits 0" ($LASTEXITCODE -eq 0)
$run = $runJson | ConvertFrom-Json
$expectVer = ($img.osVersion -split '\.')[0..2] -join '.'
Assert "guest reports its own build ($expectVer), not the host's" ($run.output -match [regex]::Escape($expectVer))
Assert "guest exit code is in the document" ($run.exitCode -eq 0)
Assert "an address was allocated" ($run.addresses.Count -ge 1)
$eps = (& $bin network endpoints --network $Network --json 2>$null) | Out-String
Assert "endpoint removed by teardown" (-not $eps.Contains("$id-ep"))
Assert "container state removed by teardown" (-not (Test-Path (Join-Path $Store "containers\$id")))

# -- the #19 transaction: injected state-write failure leaves nothing -------------------
"== container run with injected writeState failure (#19) =="
$env:HCSCTL_TEST_FAIL_WRITESTATE = '1'
& $bin container run --ref $Ref --id $id --store $Store --network $Network --cmd 'cmd /c ver' 2>&1 | Out-Null
$code = $LASTEXITCODE
Remove-Item env:HCSCTL_TEST_FAIL_WRITESTATE
Assert "injected failure exits 1" ($code -eq 1)
Assert "no container state left behind" (-not (Test-Path (Join-Path $Store "containers\$id")))
$eps = (& $bin network endpoints --network $Network --json 2>$null) | Out-String
Assert "no endpoint left behind" (-not $eps.Contains("$id-ep"))

# -- create / rm: the persisted lifecycle -------------------------------------------------
"== container create + rm (with labels, #31) =="
& $bin container create --ref $Ref --id $id --store $Store --label "owner=smoke:$PID" --label run=r1
Assert "create exits 0" ($LASTEXITCODE -eq 0)
Assert "create persisted state.json" (Test-Path (Join-Path $Store "containers\$id\state.json"))
$lsRow = ((& $bin container ls --store $Store --json 2>$null) | Out-String | ConvertFrom-Json).containers | Where-Object id -eq $id
Assert "labels round-trip through ls" ($lsRow.labels.owner -eq "smoke:$PID" -and $lsRow.labels.run -eq 'r1')
$insp = (& $bin container inspect --id $id --store $Store --json 2>$null) | Out-String | ConvertFrom-Json
Assert "labels round-trip through inspect" ($insp.state.labels.owner -eq "smoke:$PID")
& $bin container rm --id $id --store $Store --force
Assert "rm exits 0" ($LASTEXITCODE -eq 0)
Assert "rm removed the container directory" (-not (Test-Path (Join-Path $Store "containers\$id")))
$cs = Get-ComputeProcess -ErrorAction SilentlyContinue | Where-Object Id -eq $id
Assert "no compute system named $id remains" ($null -eq $cs)

# -- primary process (#33): recorded, pumped, retained, reported --------------------------
"== primary process lifecycle =="
& $bin container create --ref $Ref --id $id --store $Store --cmd 'cmd /c echo smoke-primary-line' 2>&1 | Out-Null
Assert "create with --cmd exits 0" ($LASTEXITCODE -eq 0)
& $bin container start --id $id --store $Store 2>&1 | Out-Null
Assert "start (as pump) exits 0" ($LASTEXITCODE -eq 0)
$logsJson = (& $bin container logs --id $id --store $Store --json 2>$null) | Out-String
Assert "logs exits 0 from a fresh invocation" ($LASTEXITCODE -eq 0)
$logsDoc = $logsJson | ConvertFrom-Json
Assert "retained output survives the pump" ($logsDoc.log -match 'smoke-primary-line')
Assert "primary exit code recorded" ($logsDoc.status -eq 'exited' -and $logsDoc.primary.exitCode -eq 0)
& $bin container rm --id $id --store $Store --force 2>&1 | Out-Null
Assert "primary container rm exits 0" ($LASTEXITCODE -eq 0)

# -- interactive exec (#7): piped host stdin reaches the guest and then closes ----------------
$interactiveId = "$id-interactive"
$interactiveInput = Join-Path $Store 'interactive-input.txt'
$interactiveOutput = Join-Path $Store 'interactive-output.txt'
"== container exec with forwarded stdin (#7) =="
& $bin container create --ref $Ref --id $interactiveId --store $Store 2>&1 | Out-Null
Assert "interactive container create exits 0" ($LASTEXITCODE -eq 0)
& $bin container start --id $interactiveId --store $Store 2>&1 | Out-Null
Assert "interactive container start exits 0" ($LASTEXITCODE -eq 0)
[System.IO.File]::WriteAllText($interactiveInput, 'interactive-smoke')
$hostCommand = "type `"$interactiveInput`" | `"$bin`" container exec --id $interactiveId --store `"$Store`" --cmd `"findstr .`" --interactive > `"$interactiveOutput`" 2>&1"
& cmd.exe /d /c $hostCommand
$code = $LASTEXITCODE
$interactiveText = [System.IO.File]::ReadAllText($interactiveOutput)
Assert "interactive exec exits 0 after stdin EOF" ($code -eq 0)
Assert "interactive stdin reaches the guest" ($interactiveText -match 'interactive-smoke')
& $bin container rm --id $interactiveId --store $Store --force 2>&1 | Out-Null
Assert "interactive container rm exits 0" ($LASTEXITCODE -eq 0)

# -- network inspect + private lifecycle (#15) --------------------------------------------
# Read-only inspect against the shared nat network, then a private create/inspect/rm
# round-trip. Private only: NAT create is measured on a disposable host, never here.
"== network inspect + private create/rm (#15) =="
$natInspect = (& $bin network inspect --name $Network --json 2>$null) | Out-String | ConvertFrom-Json
Assert "inspect by name exits 0" ($LASTEXITCODE -eq 0)
Assert "inspect returns the requested network" ($natInspect.name -eq $Network -and $natInspect.id)
$natById = (& $bin network inspect --id $natInspect.id --json 2>$null) | Out-String | ConvertFrom-Json
Assert "inspect by id resolves the same network" ($natById.id -eq $natInspect.id)
$privateName = "hcsctl-smoke-$PID"
$created = (& $bin network create --name $privateName --type private --json 2>$null) | Out-String | ConvertFrom-Json
Assert "private create exits 0" ($LASTEXITCODE -eq 0)
$privInspect = (& $bin network inspect --name $privateName --json 2>$null) | Out-String | ConvertFrom-Json
Assert "created network inspects by name" ($privInspect.id -eq $created.id -and $privInspect.type -eq 'Private')
Assert "created network has no endpoints" ($privInspect.endpoints.Count -eq 0)
& $bin network rm --id $created.id 2>&1 | Out-Null
Assert "private rm exits 0" ($LASTEXITCODE -eq 0)
& $bin network inspect --id $created.id 2>&1 | Out-Null
Assert "removed network no longer inspects" ($LASTEXITCODE -eq 1)

# -- image rm (fresh stores only: the working store is a shared fixture) ------------------
if (-not $SkipAcquire) {
    "== image rm =="
    & $bin image rm --ref $Ref --store $Store --blobs
    Assert "image rm exits 0" ($LASTEXITCODE -eq 0)
    Assert "layers removed" (-not (Get-ChildItem (Join-Path $Store 'layers') -ErrorAction SilentlyContinue))
}

""
"passed: $script:passed  failed: $script:failed"
Stop-Transcript
if ($script:failed -gt 0) { exit 1 }
exit 0
