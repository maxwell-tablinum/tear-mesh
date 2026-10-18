# Installs tear-mesh on one Windows machine: the binary, one local user per boundary (tm-<boundary>),
# the config, and the tearmesh service, which runs as its virtual account NT SERVICE\tearmesh.
# Run as Administrator.
#
#   deploy\setup-windows.ps1 -Machine <name> -Boundaries work,vault [-Exe tearmesh.exe] [-Stewards]
#   deploy\setup-windows.ps1 -Uninstall [-Boundaries work,vault]
#
# New users get random passwords, stored in C:\ProgramData\tearmesh\passwords.txt, which only SYSTEM
# and Administrators can read (not the service). `tearmesh launch` (runas) asks for them.
# -Stewards registers a steward per boundary user: a scheduled task that starts at boot as that user.
# -Uninstall removes the service, the stewards, the firewall rule and C:\ProgramData\tearmesh, and
# deletes the users of the boundaries given, with their profiles.
#
# The pipe accepts local callers only, including SSH sessions on this machine; other machines are
# refused. A session's boundary is the Windows account it runs as.
param(
  [string]$Machine,
  [string[]]$Boundaries = @(),
  [string]$Exe = "$PSScriptRoot\..\target\release\tearmesh.exe",
  [switch]$Stewards,
  [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run as Administrator' }

$ProgramDir = "$env:ProgramFiles\tearmesh"
$Bin = "$ProgramDir\tearmesh.exe"
$DataDir = "$env:ProgramData\tearmesh"
$StateDir = "$DataDir\state"
$Config = "$DataDir\config.toml"
$Passwords = "$DataDir\passwords.txt"
$Service = 'tearmesh'
$Account = 'NT SERVICE\tearmesh'

# Grants or takes back "Log on as a batch job", which a scheduled task with a stored password needs.
function Set-BatchLogon([string[]]$Add = @(), [string[]]$Remove = @()) {
  $inf = "$env:TEMP\tm-rights-$PID.inf"; $db = "$env:TEMP\tm-rights-$PID.sdb"
  secedit /export /cfg $inf /areas USER_RIGHTS | Out-Null
  $line = Select-String -Path $inf -Pattern '^SeBatchLogonRight = (.*)$'
  # The export names the accounts it can and gives *SID for the rest.
  $cur = @(if ($line) {
      foreach ($e in $line.Matches[0].Groups[1].Value -split ',') {
        if ($e.StartsWith('*')) { $e.Substring(1) }
        else { ([Security.Principal.NTAccount]$e).Translate([Security.Principal.SecurityIdentifier]).Value }
      }
    })
  $new = @($cur + $Add) | Where-Object { $_ -and $Remove -notcontains $_ } | Select-Object -Unique
  Set-Content $inf -Encoding Unicode -Value '[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]', ('SeBatchLogonRight = ' + (($new | ForEach-Object { "*$_" }) -join ','))
  secedit /configure /db $db /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
  Remove-Item $inf, $db -ErrorAction SilentlyContinue
}

# Replaces a folder's or file's ACL with these grants, inheriting nothing from its parent.
function Protect([string]$Path, [string[]]$Grants) {
  icacls $Path /inheritance:r /grant:r @Grants | Out-Null
  if ($LASTEXITCODE) { throw "icacls $Path failed" }
}

function Read-Passwords {
  $p = @{}
  if (Test-Path $Passwords) { Get-Content $Passwords | ForEach-Object { $u, $pw = $_ -split "`t", 2; if ($pw) { $p[$u] = $pw } } }
  $p
}

if ($Uninstall) {
  if (Get-Service $Service -ErrorAction SilentlyContinue) {
    Stop-Service $Service -Force -ErrorAction SilentlyContinue
    sc.exe delete $Service | Out-Null
  }
  Get-ScheduledTask -TaskName 'tearmesh-steward-*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
  Remove-NetFirewallRule -Name tearmesh-udp -ErrorAction SilentlyContinue
  $sids = @(foreach ($b in $Boundaries) { (Get-LocalUser "tm-$b" -ErrorAction SilentlyContinue).SID.Value })
  if ($sids) { Set-BatchLogon -Remove $sids }
  foreach ($s in $sids) {
    Get-CimInstance Win32_UserProfile -Filter "SID='$s'" | Remove-CimInstance -ErrorAction SilentlyContinue
    Remove-LocalUser -SID $s
  }
  Remove-Item -Recurse -Force $ProgramDir, $DataDir -ErrorAction SilentlyContinue
  Write-Host "tear-mesh removed$(if ($sids) { ", with users $(($Boundaries | ForEach-Object { "tm-$_" }) -join ', ')" })"
  exit
}

if (-not $Machine -or -not $Boundaries) { throw 'usage: setup-windows.ps1 -Machine <name> -Boundaries <b>,<b>... [-Exe path] [-Stewards]' }
if (-not (Test-Path $Exe)) { throw "no binary at $Exe (pass -Exe)" }

if (Get-Service $Service -ErrorAction SilentlyContinue) { Stop-Service $Service -Force }
New-Item -ItemType Directory -Force $ProgramDir | Out-Null
Copy-Item $Exe $Bin -Force

# The service comes first: NT SERVICE\tearmesh exists only once it does.
if (-not (Get-Service $Service -ErrorAction SilentlyContinue)) {
  New-Service -Name $Service -DisplayName 'tear-mesh daemon' -StartupType Automatic `
    -BinaryPathName "`"$Bin`" daemon --service --config `"$Config`"" | Out-Null
}
sc.exe config $Service obj= $Account | Out-Null
if ($LASTEXITCODE) { throw "couldn't set the service account to $Account" }
sc.exe failure $Service reset= 86400 actions= restart/5000/restart/5000/restart/60000 | Out-Null
# Like the Linux unit's empty capability set: the daemon needs no privileges.
sc.exe privs $Service SeChangeNotifyPrivilege | Out-Null

# The service reads the config and owns its state; only Administrators may change the config.
New-Item -ItemType Directory -Force $DataDir, $StateDir | Out-Null
Protect $DataDir '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "${Account}:(OI)(CI)RX"
Protect $StateDir '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "${Account}:(OI)(CI)F"

$pws = Read-Passwords
$users = [ordered]@{}
foreach ($b in $Boundaries) {
  $u = "tm-$b"
  if (-not (Get-LocalUser $u -ErrorAction SilentlyContinue)) {
    $bytes = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $pws[$u] = 'Tm1!' + [Convert]::ToBase64String($bytes)
    New-LocalUser -Name $u -Password (ConvertTo-SecureString $pws[$u] -AsPlainText -Force) -PasswordNeverExpires -AccountNeverExpires -Description "tear-mesh boundary $b" | Out-Null
    Write-Host "created user $u"
  }
  $users[$u] = $b
}
if ($pws.Count) {
  # Locked down before anything is written to it.
  if (-not (Test-Path $Passwords)) { New-Item -ItemType File $Passwords | Out-Null }
  Protect $Passwords '*S-1-5-18:F', '*S-1-5-32-544:F'
  Set-Content $Passwords -Encoding UTF8 -Value ($pws.GetEnumerator() | ForEach-Object { "$($_.Key)`t$($_.Value)" })
}

if (-not (Test-Path $Config)) {
  $admin = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  $lines = @("machine = `"$Machine`"", "admins = ['$admin']", '', '[users]') + ($users.GetEnumerator() | ForEach-Object { "$($_.Key) = `"$($_.Value)`"" })
  Set-Content $Config -Encoding ASCII -Value $lines
} else {
  Write-Host "$Config exists; left as is"
}

# Create the node key before the service starts, so both see the same key. It takes the state
# directory's ACL, which the service can read.
$id = & $Bin id --config $Config
if ($LASTEXITCODE) { throw "tearmesh id failed" }

if (-not (Get-NetFirewallRule -Name tearmesh-udp -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -Name tearmesh-udp -DisplayName 'tear-mesh (UDP in)' -Direction Inbound -Protocol UDP `
    -Program $Bin -Action Allow -Profile Private, Domain | Out-Null
}
Start-Service $Service

if ($Stewards) {
  $sids = @()
  foreach ($u in $users.Keys) {
    if (-not $pws[$u]) { Write-Host "no stored password for $u; skipping its steward"; continue }
    $sids += (Get-LocalUser $u).SID.Value
  }
  if ($sids) { Set-BatchLogon -Add $sids }
  $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  foreach ($u in $users.Keys) {
    if (-not $pws[$u]) { continue }
    $task = "tearmesh-steward-$($users[$u])"
    Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute $Bin -Argument 'steward') `
      -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings $settings -User $u -Password $pws[$u] -RunLevel Limited -Force | Out-Null
    Start-ScheduledTask -TaskName $task
    Write-Host "steward $task runs as $u; it reads %USERPROFILE%\.config\tearmesh\mailboxes.toml and offers.toml"
  }
}

Write-Host "machine $Machine, node id: $id"
Write-Host "boundary user passwords: $Passwords (SYSTEM and Administrators only)"
