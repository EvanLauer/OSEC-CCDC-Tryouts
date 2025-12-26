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

Start-Sleep -Seconds 3
