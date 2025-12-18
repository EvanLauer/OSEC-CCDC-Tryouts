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

# 3. Ensure Directory Exists
if (!(Test-Path $ScoringPath)) {
    New-Item -ItemType Directory -Path $ScoringPath -Force | Out-Null
}

# 4. User Input (Team ID)
Clear-Host
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   BLUE TEAM SCORING ENGINE SETUP" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
$TeamID = Read-Host "Enter your User ID: "

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

# Clean up old task if it exists
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Define Action: Run PowerShell, Bypass Policy, Hidden Window
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$EngineScript`""

# Define Trigger: Run immediately, then repeat every 1 minute indefinitely
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
$Trigger.Repetition.Duration = [TimeSpan]::MaxValue # Run forever

# Define Settings: Allow running on battery, do not stop if runs long
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

# Register the Task to run as SYSTEM (Highest Privileges)
try {
    Register-ScheduledTask -Action $Action -Trigger $Trigger -User "NT AUTHORITY\SYSTEM" -TaskName $TaskName -Description "Runs the Blue Team Scoring Engine" -RunLevel Highest -Settings $Settings | Out-Null
    Write-Host "[+] Scoring Engine Task Registered Successfully!" -ForegroundColor Green
    
    # Start it immediately to test
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "[+] Engine started successfully. Good luck!" -ForegroundColor Cyan
}
catch {
    Write-Host "[-] Failed to register task. Error: $_" -ForegroundColor Red
}

Start-Sleep -Seconds 3