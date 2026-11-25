# End to end on one Windows Server machine with real local users. Two daemons stand in for two
# machines: "ws" hosts boundaries work and vault, "laptop" hosts work. They use the defaults (n0
# relays and DNS). Covers the mesh and the ticket join, OS-user boundaries, the client's check of
# who owns the pipe, MCP over stdio and the hook. Creates and removes the users tme-work, tme-vault
# and tme-lap, and tme-adm, an Administrator, to check that only an elevated one counts as admin.
#
# Run as an Administrator, from an elevated console or over SSH. Clients run through scheduled
# tasks: admin commands as SYSTEM, the rest as the test users with a stored password (a batch
# logon, which needs "Log on as a batch job"; the test grants it and takes it back). The daemons
# run as SYSTEM the same way. Start-Process -Credential from SSH would be simpler, but it starts a
# child that can't open the session's window station and dies with 0xC0000142.
#
# Usage: tests\e2e-windows.ps1 [-Exe path\to\tearmesh.exe]
param([string]$Exe = "$PSScriptRoot\..\target\release\tearmesh.exe")
$ErrorActionPreference = 'Stop'
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run as Administrator' }
if (-not (Test-Path $Exe)) { Write-Host "build first: cargo build --release"; exit 2 }

$Tag = Get-Random
$T = Join-Path $env:SystemDrive "tm-e2e-$Tag"
$Users = 'tme-work', 'tme-vault', 'tme-lap', 'tme-adm'
$WsSock = "\\.\pipe\tme-ws-$Tag"
$LapSock = "\\.\pipe\tme-laptop-$Tag"
$script:Failed = $false
$Pw = @{}
$Daemons = @{}

function Pass($what) { Write-Host "PASS $what" }
function Fail($what) {
  Write-Host "FAIL $what"
  if ($script:Last) { Write-Host "  last run (exit $($script:Last.Code)): $($script:Last.All.Trim() -replace '\s*\n\s*', ' | ')" }
  $script:Failed = $true
}
function Check($what, [scriptblock]$cond) { if (& $cond) { Pass $what } else { Fail $what } }
function WaitFor([scriptblock]$cond, [int]$Secs = 30) {
  $t0 = Get-Date
  while (((Get-Date) - $t0).TotalSeconds -lt $Secs) { if (& $cond) { return $true }; Start-Sleep -Milliseconds 500 }
  $false
}

# Grants or takes back "Log on as a batch job", which a task with a stored password needs.
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

# Starts a cmd.exe line as $User (or SYSTEM) in a scheduled task, with $Env set.
function Start-Run([string]$User, [string]$Line, [hashtable]$Env = @{}, [switch]$Elevated) {
  $id = 'tme-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
  $p = "$T\run\$User\$id"
  $sets = @($Env.GetEnumerator() | ForEach-Object { "set `"$($_.Key)=$($_.Value)`"" })
  # A batch file expands %ERRORLEVEL% when it reaches the line, so the exit code is the command's.
  Set-Content "$p.cmd" -Encoding ASCII -Value (@('@echo off') + $sets + @("$Line > `"$p.out`" 2> `"$p.err`"", ">`"$p.code`" echo %ERRORLEVEL%"))
  $action = New-ScheduledTaskAction -Execute cmd.exe -Argument "/c `"$p.cmd`""
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
  if ($User -eq 'SYSTEM') {
    Register-ScheduledTask -TaskName $id -Action $action -Settings $settings -User SYSTEM -RunLevel Highest -Force | Out-Null
  } else {
    # Limited gives an Administrator its UAC-filtered token.
    $level = if ($Elevated) { 'Highest' } else { 'Limited' }
    Register-ScheduledTask -TaskName $id -Action $action -Settings $settings -User $User -Password $Pw[$User] -RunLevel $level -Force | Out-Null
  }
  Start-ScheduledTask -TaskName $id
  $p
}

# Waits for a run; returns its stdout, stderr (with stdout, in All) and exit code.
function Wait-Run([string]$p, [int]$Secs = 60) {
  $t0 = Get-Date
  while (-not ((Test-Path "$p.code") -and (Get-Item "$p.code").Length -gt 0) -and ((Get-Date) - $t0).TotalSeconds -lt $Secs) { Start-Sleep -Milliseconds 100 }
  $id = Split-Path $p -Leaf
  Stop-ScheduledTask -TaskName $id -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $id -Confirm:$false -ErrorAction SilentlyContinue
  $read = { param($f) if (Test-Path $f) { "$(Get-Content $f -Raw -Encoding UTF8)" } else { '' } }
  $out = & $read "$p.out"; $err = & $read "$p.err"
  $code = if (Test-Path "$p.code") { [int](Get-Content "$p.code") } else { -1 }
  $script:Last = [pscustomobject]@{ Out = $out; Err = $err; All = "$out`n$err"; Code = $code }
  $script:Last
}
function Run([string]$User, [string]$Line, [hashtable]$Env = @{}, [int]$Secs = 60, [switch]$Elevated) {
  Wait-Run (Start-Run $User $Line $Env -Elevated:$Elevated) $Secs
}

function Quote([string]$a) { if ($a -match '\s' -or $a -eq '') { "`"$a`"" } else { $a } }
# tm USER SOCKET MAILBOX args...: tearmesh as USER, talking to the daemon at SOCKET. No param
# block, so arguments like --subject reach $args as they are.
function tm {
  $user, $sock, $mailbox, $rest = $args
  $line = "`"$TM`" " + (($rest | ForEach-Object { Quote "$_" }) -join ' ')
  Run $user $line @{ TEARMESH_SOCKET = $sock; TEARMESH_MAILBOX = $mailbox }
}
# The command failed, and said why.
function Refused([string]$want, $r) { $r.Code -ne 0 -and $r.All.Contains($want) }
function HasBytes([string]$dir, [string]$text) {
  [bool](Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue | Select-String -SimpleMatch $text -List)
}

try {
  # Profiles of users from earlier runs, once a reboot has unloaded them.
  Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Loaded -and $_.LocalPath -match '\\tme-(work|vault|lap|adm)' -and -not (Get-LocalUser -SID $_.SID -ErrorAction SilentlyContinue) } | Remove-CimInstance -ErrorAction SilentlyContinue
  New-Item -ItemType Directory $T | Out-Null
  # SYSTEM and Administrators only; the test users get the binary and their own run directories.
  icacls $T /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  New-Item -ItemType Directory "$T\bin", "$T\run\SYSTEM" | Out-Null
  icacls "$T\bin" /grant '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
  Copy-Item $Exe "$T\bin\tearmesh.exe"
  $TM = "$T\bin\tearmesh.exe"
  foreach ($u in $Users) {
    $Pw[$u] = 'Tm1!' + [guid]::NewGuid().ToString('N')
    New-LocalUser -Name $u -Password (ConvertTo-SecureString $Pw[$u] -AsPlainText -Force) -AccountNeverExpires -PasswordNeverExpires | Out-Null
    if ($u -eq 'tme-adm') { Add-LocalGroupMember -SID S-1-5-32-544 -Member $u }
    New-Item -ItemType Directory "$T\run\$u" | Out-Null
    icacls "$T\run\$u" /grant "${u}:(OI)(CI)M" | Out-Null
  }
  Set-BatchLogon -Add ($Users | ForEach-Object { (Get-LocalUser $_).SID.Value })

  # The owner keys belong to SYSTEM, which signs with them: ssh-keygen refuses a key file that
  # names another user.
  foreach ($k in 'owner', 'backup') { Run SYSTEM "ssh-keygen -q -t ed25519 -N `"`" -C $k -f `"$T\$k`"" | Out-Null }
  @"
machine = "ws"
state_dir = '$T\ws'
socket = '$WsSock'
sync_interval_secs = 2
[users]
tme-work = "work"
tme-vault = "vault"
"@ | Set-Content "$T\ws.toml" -Encoding ASCII
  @"
machine = "laptop"
state_dir = '$T\laptop'
socket = '$LapSock'
sync_interval_secs = 2
[users]
tme-lap = "work"
"@ | Set-Content "$T\laptop.toml" -Encoding ASCII

  # The membership file needs no daemon.
  $WsId = & $TM id --config "$T\ws.toml"
  & $TM id --config "$T\laptop.toml" | Out-Null
  & $TM mesh new "$T\mesh.toml" --name home --owner-key "$T\owner.pub" --owner-key "$T\backup.pub" --boundary work --boundary vault | Out-Null
  & $TM mesh add ws $WsId --boundary work --boundary vault --file "$T\mesh.toml" | Out-Null
  $r = Run SYSTEM "`"$TM`" mesh sign `"$T\mesh.toml`" --key `"$T\owner`""
  Check "an owner key signs the membership file" { $r.Code -eq 0 -and (Test-Path "$T\mesh.toml.sig") }

  # Daemons run as SYSTEM too: one in a network logon couldn't serve its own pipe.
  foreach ($m in 'ws', 'laptop') { $Daemons[$m] = Start-Run SYSTEM "`"$TM`" daemon --config `"$T\$m.toml`"" }
  $up = { $p = @((Get-ChildItem \\.\pipe\).Name); $p -contains "tme-ws-$Tag" -and $p -contains "tme-laptop-$Tag" }
  if (-not (WaitFor $up 60)) { throw "the daemons did not start: $(@((Get-ChildItem \\.\pipe\).Name) -like 'tme-*')" }

  $r = tm SYSTEM $WsSock admin mesh apply "$T\mesh.toml"
  Check "ws adopts the signed mesh" { $r.Out -match 'applied mesh version 2' }
  $r = tm SYSTEM $WsSock admin mesh invite laptop --boundary work
  $ticket = [regex]::Match($r.Out, 'tm2-\S+').Value
  Check "ws prints a ticket for laptop" { $ticket }
  $join = Start-Run SYSTEM "`"$TM`" join $ticket" @{ TEARMESH_SOCKET = $LapSock }
  $script:pending = ''
  $waiting = WaitFor { ($script:pending = (tm SYSTEM $WsSock admin mesh pending).Out) -match 'laptop\s+code (\d{6})' }
  $code = [regex]::Match($script:pending, 'laptop\s+code (\d{6})').Groups[1].Value
  $joinSays = { [regex]::Match("$(Get-Content "$join.out" -Raw -ErrorAction SilentlyContinue)", 'code (\d{6})').Groups[1].Value }
  Check "the join waits on ws with the code laptop shows" { $waiting -and (WaitFor { (& $joinSays) -eq $code } 10) }
  $r = tm SYSTEM $WsSock admin mesh approve laptop --key "$T\owner" --yes
  Check "ws approves laptop with an owner key" { $r.Out -match 'applied mesh version 3' }
  $j = Wait-Run $join 60
  Check "laptop joins once ws approves" { $j.Code -eq 0 -and $j.Out -match 'joined; mesh version 3' }

  $id1 = (tm tme-work $WsSock builder post --to admin@laptop --subject "work note" --body "hello laptop").Out.Trim()
  tm tme-vault $WsSock builder post --to '*' --subject "vault secret" --body "do not leak" | Out-Null
  $lapInbox = { (tm tme-lap $LapSock admin inbox --all).Out }
  Check "work letter crosses machines" { WaitFor { (& $lapInbox) -match 'work note' } }
  Start-Sleep 5 # several more sync rounds
  $lapAll = & $lapInbox
  Check "vault letter is absent from laptop's inbox" { $lapAll -match 'work note' -and $lapAll -notmatch 'vault' }
  Check "vault letter is stored on ws" { HasBytes "$T\ws\boundaries" 'vault secret' }
  Check "no vault bytes anywhere on laptop's disk" { -not (Test-Path "$T\laptop\boundaries\vault.db") -and -not (HasBytes "$T\laptop" 'vault secret') }

  # Each refusal must come with its own reason, not just a non-zero exit.
  $r = tm tme-vault $WsSock builder post --to admin@laptop --subject x --body x
  Check "vault session can't address a work-only machine" { Refused 'is not in boundary vault' $r }
  $r = tm tme-vault $WsSock builder read $id1.Substring(0, 12)
  Check "vault session can't read work mail on the same machine" { Refused 'no letter' $r }
  $r = tm tme-lap $WsSock admin who
  Check "an unmapped OS user is refused" { Refused "isn't mapped" $r }
  $r = tm tme-work $WsSock builder status
  Check "a boundary user can't run admin commands" { Refused 'admin only' $r }
  $r = Run tme-adm "`"$TM`" status" @{ TEARMESH_SOCKET = $WsSock } -Elevated
  Check "an elevated Administrator runs admin commands" { $r.Code -eq 0 -and $r.Out -match '"node_id"' }
  # A limited task gets the UAC-filtered token only where local accounts' non-interactive logons
  # are filtered (LocalAccountTokenFilterPolicy unset); cloud images often turn that off.
  if ((Run tme-adm 'whoami /groups').Out -match 'S-1-5-32-544\s.*deny only') {
    $r = Run tme-adm "`"$TM`" status" @{ TEARMESH_SOCKET = $WsSock }
    Check "a non-elevated Administrator doesn't count as admin" { Refused "isn't mapped" $r }
  } else { Write-Host "SKIP non-elevated Administrator check (this machine gives a limited task the full admin token)" }
  $vaultHome = (Get-CimInstance Win32_UserProfile -Filter "SID='$((Get-LocalUser tme-vault).SID.Value)'").LocalPath
  # Not cmd's dir: it reports a folder it may not list as "File Not Found".
  $r = Run tme-work "powershell -NoProfile -Command `"Get-ChildItem '$vaultHome'`""
  Check "work user can't read the vault user's profile" { $vaultHome -and (Refused 'is denied' $r) }
  $r = Run tme-vault "type `"$T\ws\boundaries\vault.db`""
  Check "boundary users can't read the daemon's state" { Refused 'Access is denied' $r }
  if ([Security.Principal.WindowsIdentity]::GetCurrent().Groups.Value -contains 'S-1-5-2') {
    $env:TEARMESH_SOCKET = $WsSock
    $ErrorActionPreference = 'Continue' # Windows PowerShell turns redirected stderr into errors
    $o = & $TM status 2>&1 | Out-String
    $ErrorActionPreference = 'Stop'
    $env:TEARMESH_SOCKET = $null
    Check "an SSH session (a network logon) is identified and, elevated, runs admin commands" { $LASTEXITCODE -eq 0 -and $o -match 'node_id' }
  } else { Write-Host "SKIP network logon check (not in a network logon)" }

  # A program that takes the pipe name first: clients refuse it, and a daemon won't start on it.
  @'
param($name, $ready)
$sec = New-Object System.IO.Pipes.PipeSecurity
$sec.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule('Everyone', 'ReadWrite', 'Allow')))
$p = New-Object System.IO.Pipes.NamedPipeServerStream($name, 'InOut', 10, 'Byte', 'None', 4096, 4096, $sec)
Set-Content $ready ok
Start-Sleep 60
'@ | Set-Content "$T\bin\squat.ps1" -Encoding ASCII
  $squat = Start-Run tme-work "powershell -NoProfile -ExecutionPolicy Bypass -File `"$T\bin\squat.ps1`" tme-squat-$Tag `"$T\run\tme-work\squat.ready`""
  if (WaitFor { Test-Path "$T\run\tme-work\squat.ready" }) {
    $r = tm tme-lap "\\.\pipe\tme-squat-$Tag" admin who
    Check "a client refuses a pipe another user created" { Refused 'another program may have taken its name' $r }
    "machine = `"squat`"`nstate_dir = '$T\squat'`nsocket = '\\.\pipe\tme-squat-$Tag'" | Set-Content "$T\squat.toml" -Encoding ASCII
    $r = Run SYSTEM "`"$TM`" daemon --config `"$T\squat.toml`"" @{} 30
    Check "a daemon won't start on a pipe name another program holds" { Refused 'does another program have it' $r }
  } else { Fail "the squatter started" }
  Wait-Run $squat 1 | Out-Null

  $mcpIn = "$T\run\tme-lap\mcp.in"
  Set-Content $mcpIn -Encoding ASCII -Value @(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}'
    '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inbox_list","arguments":{"unread_only":false}}}')
  # ping holds stdin open for two seconds so the server answers before it sees the end.
  $r = Run tme-lap "(type `"$mcpIn`" & ping -n 3 127.0.0.1 >nul) | `"$TM`" mcp" @{ TEARMESH_SOCKET = $LapSock; TEARMESH_MAILBOX = 'admin' }
  Check "MCP server lists tools and reads the inbox over stdio" { $r.Out.Contains('"name":"send_message"') -and $r.Out.Contains('work note') }

  tm tme-work $WsSock builder post --to admin@laptop --subject "hook test" --body x | Out-Null
  WaitFor { (& $lapInbox) -match 'hook test' } | Out-Null
  $hookIn = "$T\run\tme-lap\hook.in"
  Set-Content $hookIn -Encoding ASCII -Value '{"hook_event_name":"UserPromptSubmit"}'
  $hookEnv = @{ TEARMESH_SOCKET = $LapSock; TEARMESH_MAILBOX = 'admin' }
  $h1 = Run tme-lap "`"$TM`" hook < `"$hookIn`"" $hookEnv
  $h2 = Run tme-lap "`"$TM`" hook < `"$hookIn`"" $hookEnv
  Check "hook announces new mail" { $h1.Out -match 'hook test' }
  Check "hook announces each letter only once" { $h1.Out.Trim() -and -not $h2.Out.Trim() }
}
catch {
  Fail "the test itself: $_"
}
finally {
  Get-CimInstance Win32_Process -Filter "Name='tearmesh.exe'" | Where-Object { $_.CommandLine -like "*$T*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Get-ScheduledTask -TaskName 'tme-*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
  $sids = @($Users | ForEach-Object { (Get-LocalUser $_ -ErrorAction SilentlyContinue).SID.Value } | Where-Object { $_ })
  Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -match '\\tme-' } | Stop-Process -Force -ErrorAction SilentlyContinue
  if ($sids) { Set-BatchLogon -Remove $sids }
  if ($script:Failed -and (Test-Path $T)) {
    foreach ($m in 'ws', 'laptop') { Write-Host "--- $m daemon"; Get-Content "$($Daemons[$m]).err" -Tail 20 -ErrorAction SilentlyContinue }
  }
  $kept = @(foreach ($s in $sids) {
      $p = Get-CimInstance Win32_UserProfile -Filter "SID='$s'"
      if ($p) { $p | Remove-CimInstance -ErrorAction SilentlyContinue; if (Get-CimInstance Win32_UserProfile -Filter "SID='$s'") { $p.LocalPath } }
    })
  # Windows keeps a profile loaded after a task's password logon until the next reboot.
  if ($kept) { Write-Host "NOTE: profiles left until a reboot (the next run removes them): $($kept -join ', ')" }
  $Users | ForEach-Object { Remove-LocalUser $_ -ErrorAction SilentlyContinue }
  Start-Sleep 1
  Remove-Item -Recurse -Force $T -ErrorAction SilentlyContinue
}
if ($script:Failed) { exit 1 }
Write-Host "ALL PASSED"
