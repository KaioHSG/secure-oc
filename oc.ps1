#!/usr/bin/env pwsh

# secure-oc — wraps opencode with encrypted API-key storage and
# lifecycle management for its local server.

param(
    [Parameter(Position = 0)]
    [string]$Command = "",
    [string]$Dir = "",
    [switch]$ShowValues,
    [switch]$Background,
    [switch]$Status,
    [switch]$Restart,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$dataPath   = Join-Path $PSScriptRoot "api-keys.dat"
$stateDir   = Join-Path $env:USERPROFILE ".oc"
$statePath  = Join-Path $stateDir "server-state.json"
$serverPort = 4096
$serverUrl  = "http://localhost:$serverPort"

$script:idleTimeoutMinutes = 15

# ============================================================
# crypto  –  api-keys.dat = [16-byte salt][12-byte nonce][AES-256-GCM ciphertext][16-byte tag]
# ============================================================

function Ensure-Dir {
    param([string]$p, [bool]$Protect = $false)
    if (!(Test-Path $p)) {
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        if ($Protect) { Set-DirectoryPermissions -Path $p }
    }
    elseif ($Protect) { Set-DirectoryPermissions -Path $p }
}

function Set-DirectoryPermissions {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    $ErrorActionPreference = 'Stop'
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $acl = Get-Acl -Path $Path
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $currentUser,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl
    }
    catch {}
}

function Set-StateFilePermissions {
    if (-not (Test-Path $statePath)) { return }
    $ErrorActionPreference = 'Stop'
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $acl = Get-Acl -Path $statePath
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $currentUser,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $statePath -AclObject $acl
    }
    catch {}
}

function Get-MasterPassword {
    # The master password never leaves memory; callers null it once the key is derived.
    param([string]$UserName, [string]$Message)
    $cred = Get-Credential -UserName $UserName -Message $Message
    $bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    return $plain
}

function Get-AesKey {
    param([string]$Password, [byte[]]$Salt)
    $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        [System.Text.Encoding]::UTF8.GetBytes($Password), $Salt,
        600000, [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $key = $pbkdf2.GetBytes(32); $pbkdf2.Dispose()
    return $key
}

function Read-KeysFile {
    param([string]$MasterPassword)
    $fileBytes = [System.IO.File]::ReadAllBytes($dataPath)
    $salt  = [byte[]]::new(16)
    $nonce = [byte[]]::new(12)
    $tag   = [byte[]]::new(16)
    if ($fileBytes.Length -lt 44) {
        throw "api-keys.dat is too small to be AES-GCM format. Run 'oc encrypt' to recreate it."
    }
    $cipherBytes = [byte[]]::new($fileBytes.Length - 44)
    [Array]::Copy($fileBytes,  0, $salt,   0, 16)
    [Array]::Copy($fileBytes, 16, $nonce,  0, 12)
    [Array]::Copy($fileBytes, 28, $cipherBytes, 0, $cipherBytes.Length)
    [Array]::Copy($fileBytes, 28 + $cipherBytes.Length, $tag, 0, 16)

    $aesKey = Get-AesKey -Password $MasterPassword -Salt $salt
    $plainBytes = [byte[]]::new($cipherBytes.Length)

    try {
        $aes = [System.Security.Cryptography.AesGcm]::new($aesKey)
        $aes.Decrypt($nonce, $cipherBytes, $tag, $plainBytes)
        $aes.Dispose()
    }
    catch [System.Security.Cryptography.CryptographicException] {
        throw "Wrong password, corrupted file, or old CBC format. Run 'oc encrypt' to recreate it."
    }

    return ([System.Text.Encoding]::UTF8.GetString($plainBytes) | ConvertFrom-Json)
}

function Write-KeysFile {
    param([string]$MasterPassword, [hashtable]$Keys)
    $salt  = [byte[]]::new(16)
    $nonce = [byte[]]::new(12)
    $tag   = [byte[]]::new(16)
    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($salt); $rng.GetBytes($nonce); $rng.Dispose()

    $aesKey      = Get-AesKey -Password $MasterPassword -Salt $salt
    $plainBytes  = [System.Text.Encoding]::UTF8.GetBytes(($Keys | ConvertTo-Json))
    $cipherBytes = [byte[]]::new($plainBytes.Length)

    $aes = [System.Security.Cryptography.AesGcm]::new($aesKey)
    $aes.Encrypt($nonce, $plainBytes, $cipherBytes, $tag)
    $aes.Dispose()

    $outBytes = [byte[]]::new(16 + 12 + $cipherBytes.Length + 16)
    [Array]::Copy($salt,    0, $outBytes,  0, 16)
    [Array]::Copy($nonce,   0, $outBytes, 16, 12)
    [Array]::Copy($cipherBytes, 0, $outBytes, 28, $cipherBytes.Length)
    [Array]::Copy($tag,     0, $outBytes, 28 + $cipherBytes.Length, 16)
    [System.IO.File]::WriteAllBytes($dataPath, $outBytes)
}

# ============================================================
# server state  (%USERPROFILE%\.oc\server-state.json)
# ============================================================

# DPAPI helpers — encrypt/decrypt using the Windows Data Protection API.
# Data is bound to the current user + machine; no extra key needed.
# Falls back to plaintext on non-Windows platforms with a warning.

function New-DpapiAvailable {
    try {
        [System.Security.Cryptography.ProtectedData]::Protect(
            [byte[]]@(0), [byte[]]@(0),
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        ) | Out-Null
        return $true
    }
    catch { return $false }
}

$script:dpapiAvailable = New-DpapiAvailable

function Protect-String {
    param([string]$PlainText)
    if ($script:dpapiAvailable) {
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
        $entropy    = [System.Text.Encoding]::UTF8.GetBytes("secure-oc-server-state")
        $protected  = [System.Security.Cryptography.ProtectedData]::Protect(
            $plainBytes, $entropy,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [Convert]::ToBase64String($protected)
    }
    Write-Host "WARNING: DPAPI unavailable; server password stored as plaintext." -ForegroundColor Yellow
    return $PlainText
}

function Unprotect-String {
    param([string]$ProtectedText)
    if ($script:dpapiAvailable) {
        $protectedBytes = [Convert]::FromBase64String($ProtectedText)
        $entropy        = [System.Text.Encoding]::UTF8.GetBytes("secure-oc-server-state")
        $plainBytes     = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $protectedBytes, $entropy,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [System.Text.Encoding]::UTF8.GetString($plainBytes)
    }
    return $ProtectedText
}

function New-StateHmac {
    param([string]$Mode, [string]$PasswordEnc, [int]$ServerPid, [bool]$Transition, [string]$Password)
    $hmacKey = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes("secure-oc-hmac:$Password")
    )
    $data  = "mode=$Mode`npasswordEnc=$PasswordEnc`npid=$ServerPid`ntransition=$Transition"
    $hmac  = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
    $hash  = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($data))
    $hmac.Dispose()
    return [Convert]::ToBase64String($hash)
}

function Test-StateHmac {
    param([string]$Mode, [string]$PasswordEnc, [int]$ServerPid, [bool]$Transition, [string]$Password, [string]$ExpectedHmac)
    $computed = New-StateHmac -Mode $Mode -PasswordEnc $PasswordEnc -ServerPid $ServerPid -Transition $Transition -Password $Password
    return ($computed -eq $ExpectedHmac)
}

function Get-ServerState {
    if (Test-Path $statePath) {
        $raw = Get-Content $statePath -Raw
        $obj = $raw | ConvertFrom-Json
        $passwordEnc = $obj.passwordEnc
        $password    = if ($passwordEnc) { Unprotect-String -ProtectedText $passwordEnc } else { $null }

        if ($obj.hmac) {
            if (-not (Test-StateHmac -Mode $obj.mode -PasswordEnc $obj.passwordEnc -ServerPid $obj.pid -Transition $obj.transition -Password $password -ExpectedHmac $obj.hmac)) {
                Write-Host "WARNING: server-state.json integrity check failed!" -ForegroundColor Red
                Write-Host "  The state file may be from an older version. Restart the server to fix:" -ForegroundColor Yellow
                Write-Host "  oc serve -Restart" -ForegroundColor Yellow
            }
        }

        return [PSCustomObject]@{
            mode         = $obj.mode
            password     = $password
            pid          = $obj.pid
            transition   = $obj.transition
            lastActivity = $obj.lastActivity
        }
    }
    return $null
}

function Set-ServerState {
    param([string]$Mode, [string]$Password, [int]$ServerPid, [bool]$Transition = $false)
    Ensure-Dir $stateDir -Protect $true
    Set-StateFilePermissions
    $passwordEnc = Protect-String -PlainText $Password
    $hmac = New-StateHmac -Mode $Mode -PasswordEnc $passwordEnc -ServerPid $ServerPid -Transition $Transition -Password $Password
    $state = @{
        mode         = $Mode
        passwordEnc  = $passwordEnc
        pid          = $ServerPid
        transition   = $Transition
        hmac         = $hmac
        lastActivity = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    } | ConvertTo-Json
    Set-Content -Path $statePath -Value $state
}

function Update-ServerActivity {
    # Refreshes the idle timestamp without touching password/pid/hmac.
    if (-not (Test-Path $statePath)) { return }
    try {
        $raw  = Get-Content $statePath -Raw -ErrorAction Stop
        $obj  = $raw | ConvertFrom-Json
        $obj.lastActivity = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        Set-Content -Path $statePath -Value ($obj | ConvertTo-Json)
    } catch {}
}

function Remove-ServerState {
    if (Test-Path $statePath) { Remove-Item $statePath -Force }
}

# ============================================================
# server process management
# ============================================================

# PID of the server *this session* started (may differ from the state file's)
$script:serverPid = $null

function Is-ServerRunning {
    # Alive = recorded PID exists AND the port answers.
    try {
        $state = Get-ServerState
        if ($state -and $state.pid -gt 0) {
            if (-not (Get-Process -Id $state.pid -ErrorAction SilentlyContinue)) { return $false }
        }
        $conn = [System.Net.Sockets.TcpClient]::new()
        try {
            $conn.ConnectAsync("127.0.0.1", $serverPort).Wait(2000) | Out-Null
            if ($conn.Connected) { return $true }
        }
        finally { $conn.Dispose() }
    }
    catch {}
    return $false
}

function Wait-ServerReady {
    # Polls the port for up to 30 s; dots show progress.
    Write-Host "Waiting for server" -NoNewline
    $maxWait = 30; $waited = 0
    while ($waited -lt $maxWait) {
        if (Is-ServerRunning) { Write-Host ""; return $true }
        Start-Sleep -Milliseconds 500
        $waited += 0.5
        Write-Host "." -NoNewline
    }
    Write-Host ""
    return $false
}

function Start-ServerProcess {
    # Spawns 'opencode serve' detached from this session (daemon-style).
    # API keys and the password are injected only via process environment.
    param($KeysObj, $Password)
    Ensure-Dir $stateDir -Protect $true

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName          = "opencode"
    $psi.Arguments         = "serve --port $serverPort"
    $psi.UseShellExecute   = $false
    $psi.CreateNoWindow    = $true
    $psi.RedirectStandardOutput  = $false
    $psi.RedirectStandardError   = $false
    $psi.WorkingDirectory  = $PSScriptRoot

    foreach ($prop in $KeysObj.psobject.properties) {
        $psi.EnvironmentVariables[$prop.Name] = $prop.Value
    }
    $psi.EnvironmentVariables["OPENCODE_SERVER_PASSWORD"] = $Password

    $process = [System.Diagnostics.Process]::Start($psi)
    $script:serverPid = $process.Id
    return $process.Id
}

function Start-ForegroundProcess {
    param($KeysObj, $Password)
    Ensure-Dir $stateDir -Protect $true

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName          = "opencode"
    $psi.Arguments         = "serve --port $serverPort"
    $psi.UseShellExecute   = $false
    $psi.CreateNoWindow    = $false
    $psi.RedirectStandardOutput  = $false
    $psi.RedirectStandardError   = $false
    $psi.WorkingDirectory  = $PSScriptRoot

    foreach ($prop in $KeysObj.psobject.properties) {
        $psi.EnvironmentVariables[$prop.Name] = $prop.Value
    }
    $psi.EnvironmentVariables["OPENCODE_SERVER_PASSWORD"] = $Password

    $process = [System.Diagnostics.Process]::Start($psi)
    $myPid = $process.Id
    $script:serverPid = $myPid
    Set-ServerState -Mode "foreground" -Password $Password -ServerPid $myPid
    $process.WaitForExit()

    $state = Get-ServerState
    $replaced = ($state -and ($state.transition -or $state.pid -ne $myPid))
    if ($replaced) {
        Write-Host "Server replaced by another mode." -ForegroundColor Gray
    } else {
        Remove-ServerState
        Write-Host "Server stopped." -ForegroundColor Green
    }
}

function Stop-ServerProcess {
    # Tries, in order: our in-session PID, the state-file PID, then the
    # process that owns the server port (never kills by name).
    $stopped = $false
    $state = Get-ServerState
    $targetPid = if ($script:serverPid) { $script:serverPid }
                 elseif ($state -and $state.pid -gt 0) { $state.pid }
                 else { $null }
    if (-not $targetPid) {
        try {
            $connections = Get-NetTCPConnection -LocalPort $serverPort -ErrorAction SilentlyContinue
            if ($connections) { $targetPid = $connections[0].OwningProcess }
        } catch {}
    }
    if ($targetPid) {
        try {
            $p = Get-Process -Id $targetPid -ErrorAction Stop
            $p.Kill()
            $p.WaitForExit(3000) | Out-Null
            $stopped = $true
        } catch {}
    }
    $script:serverPid = $null
    return $stopped
}

function Generate-Password {
    # A random GUID is hard to guess; other local processes can't connect
    # without this password.
    return [guid]::NewGuid().ToString().Replace("-", "").Substring(0, 16)
}

function Get-AttachCount {
    # Windows: counts unique client processes connected to the server.
    # Non-Windows: counts raw established server-side connections (less
    # accurate but still correct for zero-vs-nonzero detection).
    try {
        $conns = Get-NetTCPConnection -RemotePort $serverPort -State Established -ErrorAction Stop
        return @($conns | Select-Object OwningProcess -Unique).Count
    } catch {
        try {
            $props = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
            $all = $props.GetActiveTcpConnections()
            return @($all | Where-Object { $_.LocalEndPoint.Port -eq $serverPort -and $_.State -eq 'Established' }).Count
        } catch { return 0 }
    }
}

# ============================================================
# idle watchdog  (background mode only)
# ============================================================

function Start-IdleWatchdog {
    # Spawns a detached monitor that kills the background server after
    # $script:idleTimeoutMinutes without active sessions. Keeps refreshing
    # lastActivity while connections are established, so the clock only
    # runs after the last session closes. Dies silently once the state
    # file disappears. Re-verifies the PID before killing to avoid racing
    # a restart.
    $watchdogScript = @"
`$statePath = '$statePath'
`$serverPort = $serverPort
`$timeoutSecs = ($script:idleTimeoutMinutes * 60)
while (`$true) {
    Start-Sleep -Seconds 60
    if (-not (Test-Path `$statePath)) { break }
    try {
        `$raw = Get-Content `$statePath -Raw -ErrorAction Stop
        `$state = `$raw | ConvertFrom-Json
        if (-not `$state.lastActivity) { break }
        `$idle = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - `$state.lastActivity
        if (`$idle -le `$timeoutSecs) { continue }
    } catch { break }
    try {
        `$props = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        `$all = `$props.GetActiveTcpConnections()
        `$est = @(`$all | Where-Object { `$_.LocalEndPoint.Port -eq `$serverPort -and `$_.State -eq 'Established' }).Count
        `$raw2 = Get-Content `$statePath -Raw -ErrorAction Stop
        `$state2 = `$raw2 | ConvertFrom-Json
        if (`$state2.pid -ne `$state.pid) { continue }
        if (`$est -gt 0) {
            `$state2.lastActivity = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            Set-Content -Path `$statePath -Value (`$state2 | ConvertTo-Json)
            continue
        }
        Stop-Process -Id `$state.pid -Force -ErrorAction SilentlyContinue
        Remove-Item `$statePath -Force -ErrorAction SilentlyContinue
        break
    } catch { break }
}
"@
    $bytes   = [System.Text.Encoding]::Unicode.GetBytes($watchdogScript)
    $encoded = [Convert]::ToBase64String($bytes)

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = "pwsh"
    $psi.Arguments              = "-NoProfile -NonInteractive -EncodedCommand $encoded"
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $psi.RedirectStandardOutput = $false
    $psi.RedirectStandardError  = $false
    try { [System.Diagnostics.Process]::Start($psi) | Out-Null }
    catch { Write-Host "WARNING: Could not start idle watchdog." -ForegroundColor Yellow }
}

# ============================================================
# shared workflows  (eliminate duplication across subcommands)
# ============================================================

function Assert-Opencode {
    if (Get-Command "opencode" -ErrorAction SilentlyContinue) { return $true }
    Write-Host "Error: 'opencode' not found in PATH." -ForegroundColor Red
    Write-Host "Install it first: https://opencode.ai" -ForegroundColor Yellow
    return $false
}

function Assert-KeysFile {
    if (Test-Path $dataPath) { return $true }
    Write-Host "No api-keys.dat found. Run '" -NoNewline -ForegroundColor Yellow
    Write-Host "oc encrypt" -NoNewline -ForegroundColor Cyan
    Write-Host "' first." -ForegroundColor Yellow
    return $false
}

function Read-Keys {
    # Prompts for the master password and returns the decrypted keys,
    # or $null (after printing the error) if the password is wrong.
    $masterPass = Get-MasterPassword -UserName "Unlock" -Message "Enter master password for api-keys.dat"
    try {
        return Read-KeysFile -MasterPassword $masterPass
    }
    catch {
        Write-Host "Error: Wrong password or corrupted file." -ForegroundColor Red
        return $null
    }
    finally {
        $masterPass = $null; [GC]::Collect()
    }
}

function Read-YesNo {
    param([string]$Question)
    Write-Host $Question -ForegroundColor Red -NoNewline
    $answer = Read-Host " [y/N]"
    return ($answer -eq "y" -or $answer -eq "Y")
}

function Stop-AndCleanup {
    Stop-ServerProcess | Out-Null
    Remove-ServerState
}

# ============================================================
# subcommands
# ============================================================

function Show-Help {
    Write-Host "`noc - Secure opencode wrapper`n" -ForegroundColor Cyan
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host @"
  oc                          Start opencode (start server if needed, attach)
  oc serve                    Start a persistent server (foreground, shows logs)
  oc serve -Background        Start a persistent server in background (daemon)
  oc serve -Status            Show server status
  oc serve -Restart           Restart the server (new password, clients disconnect)
  oc encrypt                  Encrypt and store API keys
  oc decrypt                  List stored API key names
  oc decrypt -ShowValues      Show key values (use with care!)
  oc stop                     Stop the running server
  oc -Dir <path>              Attach with a specific working directory
  oc -Help                    Show this help`n
"@
    Write-Host "Workflow:" -ForegroundColor Yellow
    Write-Host @"
  1st run: oc            -> prompts for master password, starts password-protected server, attaches
  2nd run: oc            -> attaches directly (no master password), server stays alive
  oc serve               -> foreground persistent; Ctrl+C to stop
  oc serve -Background   -> background daemon; auto-stops after 15 min idle; use oc stop to shut down
  oc serve -Status       -> show current mode
  oc serve -Restart      -> kill and restart with new password`n
"@
    Write-Host "Security:" -ForegroundColor Yellow
    Write-Host @"
  Server protected with auto-generated password stored in %USERPROFILE%\.oc\server-state.json
  Password stays the same when switching modes. Changes only on restart or fresh start.
  Background servers stop automatically after 15 minutes without an active session.`n
"@
    Write-Host "Flags:" -ForegroundColor Yellow
    Write-Host @"
  -Dir <path>      Working directory for attach
  -Background      Run server in background (for oc serve)
  -Status          Show server status (for oc serve)
  -Restart         Restart server (for oc serve)
  -ShowValues      Show secret values (use with decrypt)
  -Help            Show this help`n
"@
}

function Encrypt-Main {
    $masterPass = Get-MasterPassword -UserName "MasterPassword" -Message "Set the master password to encrypt the keys file"

    $keys = @{}
    do {
        $keyName = Read-Host "Key name (e.g. OPENROUTER_API_KEY, OPENAI_API_KEY...) [leave empty to finish]"
        if ([string]::IsNullOrWhiteSpace($keyName)) { break }
        $keyValue = Read-Host "Paste the key for [$keyName]"
        if (-not [string]::IsNullOrWhiteSpace($keyValue)) {
            $keys[$keyName.Trim().ToUpper()] = $keyValue.Trim()
        }
    } while ($true)

    if ($keys.Count -eq 0) {
        Write-Host "No keys provided. Canceled." -ForegroundColor Yellow
        return
    }

    Write-KeysFile -MasterPassword $masterPass -Keys $keys
    $masterPass = $keys = $null
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    Write-Host "`nDone! 'api-keys.dat' created with all keys." -ForegroundColor Green
}

function Decrypt-Main {
    if (-not (Assert-KeysFile)) { return }

    if ($ShowValues) {
        Write-Host "WARNING: Continuing will reveal secret values on screen!" -ForegroundColor Red
    }

    $keysObj = Read-Keys
    if (-not $keysObj) { return }

    if ($ShowValues) {
        foreach ($prop in $keysObj.psobject.properties) {
            Write-Host "$($prop.Name) = $($prop.Value)"
        }
    } else {
        $keyNames = @($keysObj.psobject.properties.Name)
        Write-Host "Keys in file: $($keyNames -join ', ')" -ForegroundColor Cyan
    }
    $keysObj = $null
}

function Start-Main {
    if (-not (Assert-Opencode)) { return }

    $needsRestart = -not (Is-ServerRunning)
    if (-not $needsRestart) {
        $state = Get-ServerState
        if (-not $state -or $state.transition -or -not $state.password) {
            Write-Host "Server running but state is invalid (no password)." -ForegroundColor Yellow
            if (Read-YesNo "Restart it?") {
                Stop-AndCleanup
                $needsRestart = $true
            } else {
                Write-Host "Cannot attach: server password unknown." -ForegroundColor Red
                return
            }
        } else {
            Write-Host "Server already running on $serverUrl" -ForegroundColor Cyan
        }
    }

    if ($needsRestart) {
        if (-not (Assert-KeysFile)) { return }

        $keysObj = Read-Keys
        if (-not $keysObj) { return }

        $serverPassword = Generate-Password
        Write-Host "Starting server..." -ForegroundColor Cyan
        try {
            $serverPid = Start-ServerProcess -KeysObj $keysObj -Password $serverPassword
        }
        catch {
            Write-Host "Error: Failed to start server process: $_" -ForegroundColor Red
            return
        }
        $keysObj = $null
        Set-ServerState -Mode "background" -Password $serverPassword -ServerPid $serverPid

        if (-not (Wait-ServerReady)) {
            Write-Host "Server did not become ready in time." -ForegroundColor Red
            Stop-AndCleanup
            return
        }
        Start-IdleWatchdog
        Write-Host "Server running on $serverUrl" -ForegroundColor Green
    }

    $state = Get-ServerState
    if ($state -and $state.mode -eq "background") { Update-ServerActivity }
    $attachArgs = @("attach", $serverUrl)

    $workDir = if ($Dir) { [System.IO.Path]::GetFullPath($Dir) } else { (Get-Location).Path }
    $attachArgs += "--dir"; $attachArgs += $workDir

    if ($state.password) {
        $prevEnv = $env:OPENCODE_SERVER_PASSWORD
        $env:OPENCODE_SERVER_PASSWORD = $state.password
        try {
            $global:LASTEXITCODE = 0
            & opencode $attachArgs
        }
        finally {
            $env:OPENCODE_SERVER_PASSWORD = $prevEnv
        }
    }
    else {
        $global:LASTEXITCODE = 0
        & opencode $attachArgs
    }
}

function Serve-Main {
    if (-not (Assert-Opencode)) { return }

    if ($Status) {
        if (-not (Is-ServerRunning)) {
            Write-Host "Server: NOT RUNNING" -ForegroundColor Red
            return
        }
        $state = Get-ServerState
        $mode = if ($state) { $state.mode } else { "unknown" }
        $attachCount = Get-AttachCount
        Write-Host "Server: RUNNING" -ForegroundColor Green
        Write-Host "  URL:      $serverUrl"
        Write-Host "  Mode:     $mode"
        Write-Host "  Attached: $attachCount session$(if ($attachCount -ne 1) {'s'})"
        if ($state.password) {
            Write-Host "  Password: $($state.password.Substring(0,4))****"
        }
        if ($state -and $state.mode -eq "background" -and $state.lastActivity) {
            $idleSecs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $state.lastActivity
            $remainingSecs = [Math]::Max(0, ($script:idleTimeoutMinutes * 60) - $idleSecs)
            $remainingMin = [Math]::Ceiling($remainingSecs / 60)
            if ($attachCount -eq 0 -and $remainingSecs -gt 0) {
                Write-Host "  Idle:     $remainingMin min until auto-stop" -ForegroundColor Gray
            } elseif ($attachCount -gt 0) {
                Write-Host "  Idle:     timer paused (sessions active)" -ForegroundColor Gray
            }
        }
        return
    }

    if (-not (Assert-KeysFile)) { return }

    if ($Restart) {
        Write-Host "Restarting server..." -ForegroundColor Yellow
        $prevMode = $null
        if (Is-ServerRunning) {
            $state = Get-ServerState
            if ($state) { $prevMode = $state.mode }
            Stop-AndCleanup
        }
        if ($prevMode -eq "background") { Serve-Background } else { Serve-Foreground }
        return
    }

    if ($Background) { Switch-ToBackground; return }

    # Plain 'oc serve' → foreground.
    if (Is-ServerRunning) {
        $state = Get-ServerState
        if ($state -and $state.mode -eq "foreground") {
            Write-Host "Server is already running in foreground." -ForegroundColor Yellow
            return
        }
        if (Read-YesNo "Background server detected. Restart in foreground?") {
            $keysObj = Read-Keys
            if (-not $keysObj) { return }
            Stop-ServerProcess | Out-Null
            Write-Host "Server running on $serverUrl (foreground)" -ForegroundColor Cyan
            Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
            Start-ForegroundProcess -KeysObj $keysObj -Password $state.password
            $keysObj = $null
        } else {
            Write-Host "Aborted." -ForegroundColor Yellow
        }
        return
    }

    Serve-Foreground
}

function Switch-ToBackground {
    if (-not (Is-ServerRunning)) {
        Serve-Background
        return
    }
    $state = Get-ServerState
    if ($state -and $state.mode -eq "foreground") {
        if (-not (Read-YesNo "Foreground server detected. Restart in background?")) {
            Write-Host "Aborted." -ForegroundColor Yellow
            return
        }
        $keysObj = Read-Keys
        if (-not $keysObj) { return }
        Restart-KeepingPassword -KeysObj $keysObj -Password $state.password -FinalMode "background"
        $keysObj = $null
        return
    }
    if ($state -and $state.mode -ne "background") {
        Set-ServerState -Mode "background" -Password $state.password -ServerPid $state.pid
        Start-IdleWatchdog
        Write-Host "Server switched to background mode." -ForegroundColor Green
    } else {
        Write-Host "Server is already in background mode." -ForegroundColor Yellow
    }
}

function Restart-KeepingPassword {
    param($KeysObj, [string]$Password, [string]$FinalMode)

    $state = Get-ServerState
    Set-ServerState -Mode "transition" -Password $Password -ServerPid $state.pid -Transition $true
    Stop-ServerProcess | Out-Null
    $serverPid = Start-ServerProcess -KeysObj $KeysObj -Password $Password

    Set-ServerState -Mode "background" -Password $Password -ServerPid $serverPid
    if (-not (Wait-ServerReady)) {
        Write-Host "Failed to restart server." -ForegroundColor Red
        return
    }

    if ($FinalMode -eq "background") {
        Set-ServerState -Mode "background" -Password $Password -ServerPid $serverPid
    }
    $KeysObj = $null
    if ($FinalMode -eq "background") { Start-IdleWatchdog }
    Write-Host "Server running in background mode." -ForegroundColor Green
}

function Serve-Foreground {
    $keysObj = Read-Keys
    if (-not $keysObj) { return }

    $serverPassword = Generate-Password
    Write-Host "Server running on $serverUrl (foreground)" -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
    Start-ForegroundProcess -KeysObj $keysObj -Password $serverPassword
    $keysObj = $null
}

function Serve-Background {
    $keysObj = Read-Keys
    if (-not $keysObj) { return }

    $serverPassword = Generate-Password
    Write-Host "Starting server..." -ForegroundColor Cyan
    try {
        $serverPid = Start-ServerProcess -KeysObj $keysObj -Password $serverPassword
    }
    catch {
        Write-Host "Error: Failed to start server process: $_" -ForegroundColor Red
        return
    }
    $keysObj = $null

    Set-ServerState -Mode "background" -Password $serverPassword -ServerPid $serverPid
    if (-not (Wait-ServerReady)) {
        Write-Host "Server did not become ready in time." -ForegroundColor Red
        Stop-AndCleanup
        return
    }
    Start-IdleWatchdog
    Write-Host "Server running on $serverUrl (background)" -ForegroundColor Green
    Write-Host "Idle timeout: $([int]$script:idleTimeoutMinutes) min without activity" -ForegroundColor Gray
}

function Stop-Main {
    if (-not (Is-ServerRunning)) {
        Write-Host "Server is not running." -ForegroundColor Yellow
        Stop-AndCleanup
        return
    }

    if (Stop-ServerProcess) {
        Write-Host "Server stopped." -ForegroundColor Green
    } else {
        Write-Host "No server process found." -ForegroundColor Gray
    }
    Remove-ServerState
}

function Session-Main {
    $global:LASTEXITCODE = 0
    if ($ExtraArgs) { & opencode session @ExtraArgs } else { opencode session }
}

function Model-Main {
    $global:LASTEXITCODE = 0
    if ($ExtraArgs) { & opencode models @ExtraArgs } else { opencode models }
}

# ============================================================
# entry point
# ============================================================

if ($Help) { Show-Help; return }

switch ($Command.ToLower()) {
    "encrypt" { Encrypt-Main }
    "decrypt" { Decrypt-Main }
    "serve"   { Serve-Main }
    "session" { Session-Main }
    "model"   { Model-Main }
    "stop"    { Stop-Main }
    default   { Start-Main }
}