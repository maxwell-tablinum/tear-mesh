# Downloads this release's tear-mesh binary, checks it against the SHA-256 pinned below, and runs
# `tearmesh install`. The release workflow fills in the placeholders. In PowerShell as Administrator:
#   & ([scriptblock]::Create((irm <release>/install.ps1))) [-Machine <name> [-Boundaries work,vault]] [-Me work]
#   & ([scriptblock]::Create((irm <release>/install.ps1))) -Join <ticket>
#   & ([scriptblock]::Create((irm <release>/install.ps1))) -Uninstall
# The pinned SHA protects against a replaced binary, not against a replaced copy of this script.
# It throws and never calls exit, which would close the window it runs in.
# $env:TEARMESH_RELEASE_URL replaces the download folder (for tests).
param(
  [string]$Join,
  [string]$Machine,
  [string[]]$Boundaries = @(),
  [string]$Me,
  [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$Version = '@VERSION@'
$Sha = '@SHA_X86_64_WINDOWS@'
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run PowerShell as Administrator' }
$Boundaries = @($Boundaries | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
if ($Boundaries -and -not $Machine) { throw '-Boundaries needs -Machine' }
$dir = Join-Path ([IO.Path]::GetTempPath()) ('tearmesh-' + [guid]::NewGuid())
New-Item -ItemType Directory $dir | Out-Null
try {
  $exe = Join-Path $dir 'tearmesh.exe'
  if ($Uninstall) {
    $installed = "$env:ProgramFiles\tearmesh\tearmesh.exe"
    if (-not (Test-Path $installed)) { throw "tear-mesh isn't installed (no $installed)" }
    # Run a copy: the installed exe can't delete itself.
    Copy-Item $installed $exe
    & $exe uninstall
  } else {
    $base = if ($env:TEARMESH_RELEASE_URL) { $env:TEARMESH_RELEASE_URL } else { "https://github.com/maxwell-tablinum/tear-mesh/releases/download/v$Version" }
    Invoke-WebRequest -UseBasicParsing -Uri "$base/tearmesh-x86_64-windows.exe" -OutFile $exe
    if ((Get-FileHash -Algorithm SHA256 $exe).Hash -ne $Sha) { throw 'checksum mismatch: not installing' }
    $a = @('install')
    if ($Machine) { $a += $Machine }
    $a += $Boundaries
    if ($Me) { $a += @('--me', $Me) }
    if ($Join) { $a += @('--join', $Join) }
    & $exe @a
  }
  if ($LASTEXITCODE) { throw "tearmesh stopped (exit $LASTEXITCODE)" }
} finally {
  Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
}
