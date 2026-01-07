# ==========================================
# OSEC CCDC TRYOUT WINDOWS SCORING ENGINE
# ==========================================

# --- 0. DEBUG ---
function TestSolve {
    # Debug Challenge ID 28
    $ID = 28
    if (Test-Path "$LockDir\$ID.lock") { return }
    Submit-Solve -ChallengeID $ID -ChallengeName "Test"
}

function DebugMsg {
    msg * /TIME:30 "Debug Line"
}

# --- 1. CONFIGURATION ---
$Admin_Token  = "ctfd_4eff9761c0331fef0eafee7500b628e50b5fdcec903d74f3d97832d299a7faed"
$Team_ID_File = "C:\Scoring\TeamID.txt"
$LockDir      = "C:\Scoring\Checks"

# Ensure Lock Directory Exists (Hidden)
if (-not (Test-Path $LockDir)) {
    New-Item -Path $LockDir -ItemType Directory -Force | Out-Null
    $item = Get-Item $LockDir
    $item.Attributes = "Hidden"
}

# --- 2. HELPER FUNCTION ---
function Submit-Solve {
    param (
        [int]$ChallengeID,
        [string]$ChallengeName
    )

    # Safety check: If Team ID isn't set yet, do nothing.
    if (-not (Test-Path $Team_ID_File)) { return }
    
    $TeamID = (Get-Content $Team_ID_File -Raw).Trim()

    $Headers = @{
        "Authorization" = "Token $Admin_Token"
        "Content-Type"  = "application/json"
    }

    $Body = @{
        challenge_id = $ChallengeID
        user_id      = $TeamID
        type         = "correct"
        provided     = "Scripted"
    } | ConvertTo-Json

    try {
        # 1. Send API Request
        $Response = Invoke-RestMethod -Uri "http://192.168.103.243:4000/api/v1/submissions" -Method Post -Headers $Headers -Body $Body -ErrorAction Stop
        
        # 2. CREATE LOCKFILE (Prevents this check from running again)
        New-Item -Path "$LockDir\$ChallengeID.lock" -ItemType File -Force | Out-Null
        
        # 3. Success Notification
        msg * /TIME:5 "CORRECT! $ChallengeName Fixed. Points Awarded."
    }
    catch {
        $httpError = $_.Exception.Message

        $stream = $_.Exception.Response.GetResponseStream()
        if ($stream) {
            $reader = New-Object System.IO.StreamReader($stream)
            $apiDetails = $reader.ReadToEnd()
        }
        
        # Only alert if it's NOT a "Already Solved" error (which shouldn't happen with locks, but just in case)
        if ($httpError -notmatch "already solved") {
             msg * /TIME:30 "HTTP ERROR: $httpError"
        }
    }
}

# --- 3. CHECK FUNCTIONS ---

# Challenge 1: Insecure Password
function Check-PasswordChanged {
    $ID = 1
    if (Test-Path "$LockDir\$ID.lock") { return }

    $CompetitionStart = Get-Date "01/01/2026 1:01:01 AM"
    try {
        $User = Get-ADUser -Identity "Administrator" -Properties PasswordLastSet
        if ($User.PasswordLastSet -gt $CompetitionStart) {
            Submit-Solve -ChallengeID $ID -ChallengeName "Insecure Password"
        }
    } catch {}
}

# Challenge 2: Password Policies
function Check-PasswordPolicies {
    $ID = 2
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $Policy = Get-ADDefaultDomainPasswordPolicy
        $Clean_Complexity = $Policy.ComplexityEnabled -eq $true
        $Clean_Length = $Policy.MinPasswordLength -ge 6
        $Clean_History = $Policy.PasswordHistoryCount -ge 1
        $Clean_Age = $Policy.MaxPasswordAge.TotalSeconds -gt 0

        if ($Clean_Complexity -and $Clean_Length -and $Clean_History -and $Clean_Age) {
            Submit-Solve -ChallengeID $ID -ChallengeName "Password Policy"
        }
    } catch {}
}

# Challenge 3: Windows Firewall
function Check-Firewall {
    $ID = 3
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $Profiles = Get-NetFirewallProfile -Profile Domain,Public,Private
        $EnabledCount = ($Profiles | Where-Object {$_.Enabled -eq $True}).Count

        if ($EnabledCount -eq 3) {
            Submit-Solve -ChallengeID $ID -ChallengeName "Firewall Enabled"
        }
    } catch {}
}

# Challenge 4: RDP Network Level Authentication (NLA)
function Check-NLA {
    $ID = 4
    if (Test-Path "$LockDir\$ID.lock") { return }

    $Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP'
    $Name = 'UserAuthentication'

    try {
        $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        if ($CurrentValue -eq 1) {
            Submit-Solve -ChallengeID $ID -ChallengeName "RDP NLA Enabled"
        }
    } catch {}
}

# Challenge 5: Windows Updates Service
function Check-Updates {
    $ID = 5
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $Service = Get-Service -Name wuauserv
        if ($Service.StartType -ne "Disabled") {
            Submit-Solve -ChallengeID $ID -ChallengeName "Windows Updates Enabled"
        }
    } catch {}
}

# Challenge 6: Windows Defender
function Check-Defender {
    $ID = 6
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $Prefs = Get-MpPreference
        if ($Prefs.DisableRealtimeMonitoring -eq $false) {
             Submit-Solve -ChallengeID $ID -ChallengeName "Windows Defender Enabled"
        }
    } catch {}
}

# Challenge 7: RDP Service (Should be Disabled)
function Check-RDPDisabled {
    $ID = 7
    if (Test-Path "$LockDir\$ID.lock") { return }

    $Path = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
    $Name = "fDenyTSConnections"

    try {
        $Val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        if ($Val -eq 1) {
             Submit-Solve -ChallengeID $ID -ChallengeName "RDP Disabled"
        }
    } catch {}
}

# Challenge 8: Account Lockout Policy
function Check-AccountLockout {
    $ID = 8
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $Policy = Get-ADDefaultDomainPasswordPolicy
        $Threshold_Fixed = $Policy.LockoutThreshold -gt 0
        $Duration_Fixed = $Policy.LockoutDuration.TotalMinutes -gt 0

        if ($Threshold_Fixed -and $Duration_Fixed) {
             Submit-Solve -ChallengeID $ID -ChallengeName "Account Lockout Enabled"
        }
    } catch {}
}

# Challenge 9: Advanced Audit Policy (Logon)
function Check-AuditLogon {
    $ID = 9
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $Policy = auditpol /get /subcategory:"Logon"
        if ($Policy -match "Success" -or $Policy -match "Failure") {
            Submit-Solve -ChallengeID $ID -ChallengeName "Logon Auditing"
        }
    } catch {}
}

# Challenge 10: User Account Control (UAC)
function Check-UAC {
    $ID = 10
    if (Test-Path "$LockDir\$ID.lock") { return }

    $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $Name = "EnableLUA"

    try {
        $Val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        if ($Val -ne 0) {
            Submit-Solve -ChallengeID $ID -ChallengeName "UAC Enabled"
        }
    } catch {}
}

# Challenge 11: SMBv1 Protocol (Should be Disabled)
function Check-SMB1 {
    $ID = 11
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        if ((Get-SmbServerConfiguration).EnableSMB1Protocol -eq $false) {
            Submit-Solve -ChallengeID $ID -ChallengeName "SMBv1 Disabled"
        }
    } catch {}
}

# Challenge 12: Windows Time Service (w32time)
function Check-TimeService {
    $ID = 12
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $Service = Get-Service -Name w32time
        if ($Service.StartType -ne "Disabled") {
            Submit-Solve -ChallengeID $ID -ChallengeName "Time Service Enabled"
        }
    } catch {}
}

# Challenge 13: Firewall Inbound Rules (Stop "Allow All")
function Check-FirewallInbound {
    $ID = 13
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $BlockRules = @(Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue)
        if ($BlockRules.Count -gt 0) {
            Submit-Solve -ChallengeID $ID -ChallengeName "Firewall Rules Reset"
        }
    } catch {}
}

# Challenge 14: Insecure SMB Share (CompanyBackups)
function Check-OpenShare {
    $ID = 14
    if (Test-Path "$LockDir\$ID.lock") { return }

    $ShareName = "CompanyBackups"
    try {
        $ShareExists = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
        if (-not $ShareExists) {
            Submit-Solve -ChallengeID $ID -ChallengeName "Insecure Share Secured"
            return
        }

        $Permissions = Get-SmbShareAccess -Name $ShareName
        $Insecure = @($Permissions | Where-Object { 
            ($_.AccountName -match "Everyone" -or $_.AccountName -match "Anonymous") -and $_.AccessControlType -eq "Allow"
        })

        if ($Insecure.Count -eq 0) {
            Submit-Solve -ChallengeID $ID -ChallengeName "Insecure Share Secured"
        }
    } catch {}
}

# Challenge 15: WinRM TrustedHosts (Remove Wildcard)
function Check-WinRMTrustedHosts {
    $ID = 15
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $Value = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
        if ($Value -ne "*") {
            Submit-Solve -ChallengeID $ID -ChallengeName "WinRM TrustedHosts Secured"
        }
    } catch {}
}

# Challenge 16: PowerShell Execution Policy
function Check-ExecutionPolicy {
    $ID = 16
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $Policy = (Get-ExecutionPolicy -Scope LocalMachine).ToString()
        if ($Policy -eq "RemoteSigned" -or $Policy -eq "Restricted") {
            Submit-Solve -ChallengeID $ID -ChallengeName "Execution Policy Secured"
        }
    } catch {}
}

# Challenge 17: Guest Account (Should be Disabled)
function Check-GuestDisabled {
    $ID = 17
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $Guest = Get-ADUser -Identity "Guest"
        if ($Guest.Enabled -eq $false) {
            Submit-Solve -ChallengeID $ID -ChallengeName "Guest Account Disabled"
        }
    } catch {}
}

# Challenge 18: Bad Users Deleted
function Check-BadUsers {
    $ID = 18
    if (Test-Path "$LockDir\$ID.lock") { return }

    $BadUsers = @("Support", "Temp_Admin", "krbtgt_support", "HealthMailbox01")
    $DetectedBadUsers = 0

    foreach ($Name in $BadUsers) {
        try {
            $User = Get-ADUser -Identity $Name -ErrorAction Stop
            $DetectedBadUsers++
        } catch {}
    }

    if ($DetectedBadUsers -eq 0) {
        Submit-Solve -ChallengeID $ID -ChallengeName "Bad Accounts Deleted"
    }
}

# Challenge 19: Bad Groups Deleted
function Check-BadGroups {
    $ID = 19
    if (Test-Path "$LockDir\$ID.lock") { return }

    $BadGroups = @("Helpdesk Tier 1", "Legacy Printers", "Contractors")
    $DetectedBadGroups = 0

    foreach ($Group in $BadGroups) {
        try {
            $Target = Get-ADGroup -Identity $Group -ErrorAction Stop
            $DetectedBadGroups++
        } catch {}
    }

    if ($DetectedBadGroups -eq 0) {
        Submit-Solve -ChallengeID $ID -ChallengeName "Bad Groups Deleted"
    }
}

# Challenge 20: Bad DNS Forwarder Removed
function Check-DNSForwarder {
    $ID = 20
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $Forwarders = (Get-DnsServerForwarder -ErrorAction SilentlyContinue).IPAddress
        if ($Forwarders -notcontains "10.99.99.99") {
            Submit-Solve -ChallengeID $ID -ChallengeName "Bad DNS Forwarder Removed"
        }
    } catch {}
}

# Challenge 21: Frances fucked up CTFd
# (Empty in original)

# Challenge 22: DNS Zone Transfers (Should be Restricted)
function Check-ZoneTransfer {
    $ID = 22
    if (Test-Path "$LockDir\$ID.lock") { return }

    $ZoneName = "osec.local"
    try {
        $Zone = Get-DnsServerZone -Name $ZoneName -ErrorAction Stop
        if ($Zone.SecureSecondaries -ne "TransferAnyServer") {
            Submit-Solve -ChallengeID $ID -ChallengeName "Zone Transfers Secured"
        }
    } catch {}
}

# Challenge 23: DHCP Scope Options (Bad Router)
function Check-DHCPScope {
    $ID = 23
    if (Test-Path "$LockDir\$ID.lock") { return }

    $TargetScope = "10.0.0.0"
    try {
        $ScopeExists = Get-DhcpServerv4Scope -ScopeId $TargetScope -ErrorAction SilentlyContinue
        if (-not $ScopeExists) {
            Submit-Solve -ChallengeID $ID -ChallengeName "DHCP Scope Fixed"
            return
        }

        $RouterOption = Get-DhcpServerv4OptionValue -ScopeId $TargetScope -OptionId 3 -ErrorAction SilentlyContinue
        if ($RouterOption.Value -ne "10.0.0.254") {
            Submit-Solve -ChallengeID $ID -ChallengeName "DHCP Scope Fixed"
        }
    } catch {}
}

# Challenge 24: IIS Directory Browsing (Should be Disabled)
function Check-DirectoryBrowsing {
    $ID = 24
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        $Property = Get-WebConfigurationProperty -Filter //directoryBrowse -PSPath 'IIS:\Sites\Default Web Site' -Name enabled -ErrorAction Stop
        if ($Property.Value -eq $False) {
            Submit-Solve -ChallengeID $ID -ChallengeName "Directory Browsing Disabled"
        }
    } catch {}
}

# Challenge 25: IIS App Pool Identity (Should NOT be LocalSystem)
function Check-AppPoolIdentity {
    $ID = 25
    if (Test-Path "$LockDir\$ID.lock") { return }

    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        $Identity = Get-ItemProperty -Path 'IIS:\AppPools\DefaultAppPool' -Name 'processModel.identityType'
        $Val = ($Identity).ToString()
        
        if ($Val -ne "LocalSystem") {
            Submit-Solve -ChallengeID $ID -ChallengeName "App Pool Secured"
        }
    } catch {}
}

# Challenge 26: Remove ASP.NET 3.5 (Legacy/Unused)
function Check-ASPNet {
    $ID = 26
    if (Test-Path "$LockDir\$ID.lock") { return }
    # Place holder logic
}

# Challenge 29: Clippy
function Check-Clippy {
    $ID = 29
    if (Test-Path "$LockDir\$ID.lock") { return }

    $clippyProcess = Get-Process "SystemColorMgr" -ErrorAction SilentlyContinue
    if (-not $clippyProcess) {
        Submit-Solve -ChallengeID $ID -ChallengeName "Malware Removed"
    }
}


# --- 4. EXECUTE ---
#TestSolve
Check-PasswordChanged
Check-PasswordPolicies
Check-Firewall
Check-NLA
Check-Updates
Check-Defender
Check-RDPDisabled
Check-AccountLockout
Check-AuditLogon
Check-UAC
Check-SMB1
Check-TimeService
Check-FirewallInbound
Check-OpenShare
Check-WinRMTrustedHosts
Check-ExecutionPolicy
Check-GuestDisabled
Check-BadUsers
Check-BadGroups
Check-DNSForwarder
Check-ZoneTransfer
Check-DHCPScope
Check-DirectoryBrowsing
Check-AppPoolIdentity
Check-Clippy