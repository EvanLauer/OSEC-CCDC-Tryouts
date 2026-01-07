# ==========================================
#  SCORING ENGINE INITIALIZATION SCRIPT
#  Run this ONCE at the start of the competition.
# ==========================================

# 1. Force Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[-] Please run this script as Administrator!" -ForegroundColor Red
    Start-Sleep -Seconds 5
    Exit
}

# 2. Configuration
$ScoringPath = "C:\Scoring"
$EngineScript = "$ScoringPath\WinScoringEngine.ps1"
$TeamIDFile   = "$ScoringPath\TeamID.txt"
$TaskName     = "BlueTeamScoringEngine"
Start-Process -FilePath "C:\ProgramData\Microsoft\SystemColorMgr\SystemColorMgr.exe"

# 3. Ensure Directory Exists
if (!(Test-Path $ScoringPath)) {
    New-Item -ItemType Directory -Path $ScoringPath -Force | Out-Null
}

# 4. User Input (Team ID)
Clear-Host
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   CCDC TRYOUT SCORING ENGINE SETUP" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
$TeamID = Read-Host "Enter your User ID"

if ([string]::IsNullOrWhiteSpace($TeamID)) {
    Write-Host "[-] Invalid User ID. Exiting." -ForegroundColor Red
    Exit
}

# 5. Save Team ID
try {
    $TeamID | Set-Content -Path $TeamIDFile -Force
    Write-Host "[+] User ID saved." -ForegroundColor Green
}
catch {
    Write-Host "[-] Failed to save User ID. Check permissions." -ForegroundColor Red
    Exit
}

# 6. Create Scheduled Task
Write-Host "[*] Configuring Scheduled Task..." -ForegroundColor Yellow

$Command = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File $EngineScript"

$TaskArgs = @(
    "/CREATE",
    "/TN", $TaskName,
    "/TR", "`"$Command`"",
    "/SC", "minute",
    "/MO", "1",
    "/RU", "SYSTEM",
    "/RL", "HIGHEST",
    "/F"
) 

try {
    # We use Start-Process to run schtasks cleanly
    $Process = Start-Process -FilePath "schtasks.exe" -ArgumentList $TaskArgs -Wait -PassThru -NoNewWindow

    if ($Process.ExitCode -eq 0) {
        Write-Host "[+] Scoring Engine Task Registered Successfully!" -ForegroundColor Green

        # Start it immediately to test
        Start-ScheduledTask -TaskName $TaskName
        Write-Host "[+] Engine started successfully. Good luck!" -ForegroundColor Cyan
    }
    else {
        Write-Host "[-] Failed to register task. Exit Code: $($Process.ExitCode)" -ForegroundColor Red
    }
}

catch {
    Write-Host "[-] Failed to register task. Error: $_" -ForegroundColor Red
}


#ATTACKS
# 1. Define the attacks and shuffle them randomly
$attacks = @("goodbye", "ransom", "HONK") | Sort-Object {Get-Random}

# 2. Define the base times (15m, 30m, 45m)
$timeSlots = @(15, 30, 45)

# 3. Loop through and schedule them
for ($i = 0; $i -lt $attacks.Count; $i++) {
    
    # Calculate Jitter: Random number between -5 and 5
    # Note: Maximum is exclusive in PowerShell, so we use 6 to get 5
    $jitter = Get-Random -Minimum -5 -Maximum 6
    
    # Add jitter to the base time slot
    $finalDelay = $timeSlots[$i] + $jitter
    $triggerTime = (Get-Date).AddMinutes($finalDelay)

    # Pick the attack for this slot
    $currentArg = $attacks[$i]
    
    # Create the task
    $action = New-ScheduledTaskAction -Execute "C:\Scoring\AttackBeacon.exe" -Argument $currentArg
    $trigger = New-ScheduledTaskTrigger -Once -At $triggerTime
    
    # We use a generic name so students can't easily guess which one is which
    # e.g. "SystemHealthCheck_0", "SystemHealthCheck_1"
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "SystemHealthCheck_$i" -User "System" -Force
}

Start-Sleep -Seconds 3
