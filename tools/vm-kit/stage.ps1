# Build the folder a guest needs, from this machine.
#
# The guest cannot reach this repository over its own network in the setup this
# product is tested in, and copying the whole repository is copying a build tree:
# the guest needs four files and two scripts. This builds that folder and zips
# it, so the transfer is one file and what is inside it is knowable.

param(
    [string]$Output = (Join-Path $PSScriptRoot '..\..\target\vm-stage')
)

$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$release = Join-Path $repo 'target\release'
$driver = Join-Path $repo 'target\driver-test'
$stage = Join-Path $Output ("wenle-vm-{0}" -f (Get-Date -Format 'yyyyMMdd'))

if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stage 'tools\vm-kit') -Force | Out-Null

foreach ($name in 'wenle-av-service.exe', 'wenle.exe', 'wenle-gui.exe', 'wenle-scan.exe') {
    $source = Join-Path $release $name
    if (-not (Test-Path $source)) { throw "no $name in $release; build first" }
    Copy-Item $source $stage -Force
}
foreach ($name in 'wenle-test-driver.cer', 'wenle-test-driver.pfx') {
    Copy-Item (Join-Path $driver $name) $stage -Force
}
# The signed driver currently installed is the one this host runs; the guest
# should run the same build rather than a signed artefact from an older one.
Copy-Item 'C:\Windows\System32\drivers\WenleAvFilter.sys' (Join-Path $stage 'WenleAvFilter.sys') -Force
# The AMSI provider, so script content is examined before it runs.
Copy-Item (Join-Path $release 'av_amsi.dll') (Join-Path $stage 'av_amsi.dll') -Force

Copy-Item (Join-Path $PSScriptRoot 'install.ps1') (Join-Path $stage 'tools\vm-kit') -Force
Copy-Item (Join-Path $PSScriptRoot 'collect.ps1') (Join-Path $stage 'tools\vm-kit') -Force
Copy-Item (Join-Path $PSScriptRoot 'ingest.ps1') (Join-Path $stage 'tools\vm-kit') -Force
Copy-Item (Join-Path $PSScriptRoot 'techniques.ps1') (Join-Path $stage 'tools\vm-kit') -Force
Copy-Item (Join-Path $repo 'tools\behaviour-corpus.ps1') (Join-Path $stage 'tools') -Force

$readme = @'
Wenle EDR: guest install and collection

1. Copy this folder into the guest.
2. Elevated PowerShell in the folder:
       powershell -NoProfile -ExecutionPolicy Bypass -File tools\vm-kit\install.ps1
   If it says test signing was enabled, restart the guest and run it again.
3. Collect behaviour (corpus families + ATT&CK techniques):
       powershell -NoProfile -ExecutionPolicy Bypass -File tools\vm-kit\collect.ps1 -Rounds 2
4. Copy C:\WenleAV\vm-collection\collection-*.zip back to the host and run
       tools\vm-kit\ingest.ps1 -Zip <the zip>
'@
Set-Content -Path (Join-Path $stage 'README.txt') -Value $readme -Encoding ASCII

$zip = "$stage.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
Write-Output ("staged: {0}" -f $stage)
Write-Output ("zip:    {0} ({1:N1} MB)" -f $zip, ((Get-Item $zip).Length / 1MB))
