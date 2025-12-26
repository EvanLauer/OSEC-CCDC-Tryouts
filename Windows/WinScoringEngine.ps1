# ==========================================
# OSEC CCDC TRYOUT WINDOWS SCORING ENGINE
# ==========================================

# --- 0. DEBUG ---
function TestSolve {
    Submit-Solve -ChallengeID 28 -ChallengeName "Test"
}

function DebugMsg {
    msg * /TIME:30 "Debug Line"
}

#$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# --- 1. CONFIGURATION ---
$Admin_Token  = "ctfd_4eff9761c0331fef0eafee7500b628e50b5fdcec903d74f3d97832d299a7faed"
$Team_ID_File = "C:\Scoring\TeamID.txt"

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
        $Response = Invoke-RestMethod -Uri "http://192.168.103.243:4000/api/v1/submissions" -Method Post -Headers $Headers -Body $Body -ErrorAction Stop
        
        # === SUCCESS NOTIFICATION ===
        msg * /TIME:5 "CORRECT! $ChallengeName Fixed. Points Awarded."
    }
    catch {
        $httpError = $_.Exception.Message

        $stream = $_.Exception.Response.GetResponseStream()
        if ($stream) {
            $reader = New-Object System.IO.StreamReader($stream)
            $apiDetails = $reader.ReadToEnd()
        }

        msg * /TIME:30 "HTTP ERROR: $httpError"
    }
}

# --- 3. CHECK FUNCTIONS ---

# Challenge 1: Insecure Password - WORKING
function Check-PasswordChanged {
    $CompetitionStart = Get-Date "01/01/2026 1:01:01 AM"
    
    try {
        $User = Get-ADUser -Identity "Administrator" -Properties PasswordLastSet
        if ($User.PasswordLastSet -gt $CompetitionStart) {
            Submit-Solve -ChallengeID 1 -ChallengeName "Insecure Password"
        }
    } catch {}
}

# Challenge 2: Password Policies - WORKING
function Check-PasswordPolicies {
    try {
        # Get the current policy for the domain
        $Policy = Get-ADDefaultDomainPasswordPolicy
        
        # CRITERIA:
        # 1. Complexity must be ENABLED
        $Clean_Complexity = $Policy.ComplexityEnabled -eq $true
        
        # 2. Length must be at least 6 chars (Standard best practice)
        $Clean_Length = $Policy.MinPasswordLength -ge 6
        
        # 3. History must be enforced (remember at least 1 password)
        $Clean_History = $Policy.PasswordHistoryCount -ge 1
        
        # 4. Max Age must not be 0 (0 means "Never Expires")
        $Clean_Age = $Policy.MaxPasswordAge.TotalSeconds -gt 0

        # If ALL settings are fixed, award points
        if ($Clean_Complexity -and $Clean_Length -and $Clean_History -and $Clean_Age) {
            Submit-Solve -ChallengeID 2 -ChallengeName "Password Policy"
        }
    } catch {}
}

# Challenge 3: Windows Firewall - WORKING
function Check-Firewall {
    try {
        # Get the status of all 3 profiles (Domain, Public, Private)
        $Profiles = Get-NetFirewallProfile -Profile Domain,Public,Private
        
        # We count how many are currently Enabled ($true)
        $EnabledCount = ($Profiles | Where-Object {$_.Enabled -eq $True}).Count

        # If all 3 are enabled, they pass.
        if ($EnabledCount -eq 3) {
            Submit-Solve -ChallengeID 3 -ChallengeName "Firewall Enabled"
        }
    } catch {}
}

# Challenge 4: RDP Network Level Authentication (NLA) - WORKING
function Check-NLA {
    $Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP'
    $Name = 'UserAuthentication'

    try {
        # Get the current registry value
        $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name

        # Value 1 = NLA Enabled (Secure). Value 0 = Disabled (Vulnerable).
        if ($CurrentValue -eq 1) {
            Submit-Solve -ChallengeID 4 -ChallengeName "RDP NLA Enabled"
        }
    } catch {}
}

# Challenge 5: Windows Updates Service - WORKING
function Check-Updates {
    try {
        # Get the service configuration
        $Service = Get-Service -Name wuauserv
        
        # We check if the StartType is NOT Disabled. 
        # (It can be Manual or Automatic, both are acceptable fixes).
        if ($Service.StartType -ne "Disabled") {
            Submit-Solve -ChallengeID 5 -ChallengeName "Windows Updates Enabled"
        }
    } catch {}
}

# Challenge 6: Windows Defender - WORKING
function Check-Defender {
    try {
        $Prefs = Get-MpPreference
        
        # We specifically check Real-time Monitoring.
        # If "DisableRealtimeMonitoring" is False, then Defender is ON (Fixed).
        if ($Prefs.DisableRealtimeMonitoring -eq $false) {
             Submit-Solve -ChallengeID 6 -ChallengeName "Windows Defender Enabled"
        }
    } catch {}
}

# Challenge 7: RDP Service (Should be Disabled) - WORKING
function Check-RDPDisabled {
    $Path = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
    $Name = "fDenyTSConnections"

    try {
        $Val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        
        # 1 = Deny Connections (Secure/Disabled)
        # 0 = Allow Connections (Vulnerable/Enabled)
        if ($Val -eq 1) {
             Submit-Solve -ChallengeID 7 -ChallengeName "RDP Disabled"
        }
    } catch {}
}

# Challenge 8: Account Lockout Policy - WORKING
function Check-AccountLockout {
    try {
        $Policy = Get-ADDefaultDomainPasswordPolicy
        
        # CRITERIA:
        # 1. Threshold must be > 0 (0 means "Account will not lock out")
        $Threshold_Fixed = $Policy.LockoutThreshold -gt 0
        
        # 2. Duration must be > 0 minutes
        $Duration_Fixed = $Policy.LockoutDuration.TotalMinutes -gt 0

        if ($Threshold_Fixed -and $Duration_Fixed) {
             Submit-Solve -ChallengeID 8 -ChallengeName "Account Lockout Enabled"
        }
    } catch {}
}

# Challenge 9: Advanced Audit Policy (Logon) - WORKING
function Check-AuditLogon {
    try {
        # We use the native tool 'auditpol' to get the current status of the Logon subcategory
        # We perform a case-insensitive string match.
        $Policy = auditpol /get /subcategory:"Logon"

        # If the output contains "Success" or "Failure", they turned it on.
        if ($Policy -match "Success" -or $Policy -match "Failure") {
            Submit-Solve -ChallengeID 9 -ChallengeName "Logon Auditing"
        }
    } catch {}
}

# Challenge 10: User Account Control (UAC) - WORKING
function Check-UAC {
    $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $Name = "EnableLUA"

    try {
        $Val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        
        # 0 = Disabled (Vulnerable)
        # 1 = Enabled (Secure)
        if ($Val -ne 0) {
            Submit-Solve -ChallengeID 10 -ChallengeName "UAC Enabled"
        }
    } catch {}
}

# Challenge 11: SMBv1 Protocol (Should be Disabled) - WORKING
function Check-SMB1 {
    try {
        # We check the running configuration.
        # If EnableSMB1Protocol is False, they successfully disabled it.
        if ((Get-SmbServerConfiguration).EnableSMB1Protocol -eq $false) {
            Submit-Solve -ChallengeID 11 -ChallengeName "SMBv1 Disabled"
        }
    } catch {}
}

# Challenge 12: Windows Time Service (w32time) - WORKING
function Check-TimeService {
    try {
        $Service = Get-Service -Name w32time
        
        # If StartType is NOT Disabled (Manual or Automatic is fine), they fixed it.
        if ($Service.StartType -ne "Disabled") {
            Submit-Solve -ChallengeID 12 -ChallengeName "Time Service Enabled"
        }
    } catch {}
}

# Challenge 13: Firewall Inbound Rules (Stop "Allow All") - WORKING
function Check-FirewallInbound {
    try {
        # The misconfig sets ALL inbound rules to "Allow". 
        # To pass, the student must have restored rules that "Block" traffic.
        $BlockRules = @(Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue)
        
        # If we find at least 1 rule that Blocks traffic, they fixed the "Allow All" state.
        if ($BlockRules.Count -gt 0) {
            Submit-Solve -ChallengeID 13 -ChallengeName "Firewall Rules Reset"
        }
    } catch {}
}

# Challenge 14: Insecure SMB Share (CompanyBackups) - WORKING
function Check-OpenShare {
    $ShareName = "CompanyBackups"
    try {
        # 1. Check if the share still exists
        $ShareExists = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue

        # If they deleted the share entirely, the data leak is gone. PASS.
        if (-not $ShareExists) {
            Submit-Solve -ChallengeID 14 -ChallengeName "Insecure Share Secured"
            return
        }

        # 2. If share exists, check permissions
        $Permissions = Get-SmbShareAccess -Name $ShareName
        
        # We fail if we see "Everyone" or "Anonymous Logon" in the access list
        $Insecure = @($Permissions | Where-Object { 
            ($_.AccountName -match "Everyone" -or $_.AccountName -match "Anonymous") -and $_.AccessControlType -eq "Allow"
        })

        if ($Insecure.Count -eq 0) {
            Submit-Solve -ChallengeID 14 -ChallengeName "Insecure Share Secured"
        }
    } catch {}
}

# Challenge 15: WinRM TrustedHosts (Remove Wildcard) - WORKING
function Check-WinRMTrustedHosts {
    try {
        # Get the current TrustedHosts value
        $Value = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value

        # The vulnerability is setting this to "*".
        # If the value is NOT "*", they have fixed the wide-open trust.
        if ($Value -ne "*") {
            Submit-Solve -ChallengeID 15 -ChallengeName "WinRM TrustedHosts Secured"
        }
    } catch {}
}

# Challenge 16: PowerShell Execution Policy - WORKING
function Check-ExecutionPolicy {
    try {
        # Get the effective execution policy
        $Policy = (Get-ExecutionPolicy -Scope LocalMachine).ToString()

        # The prompt requires "RemoteSigned" or "Restricted" to pass.
        if ($Policy -eq "RemoteSigned" -or $Policy -eq "Restricted") {
            Submit-Solve -ChallengeID 16 -ChallengeName "Execution Policy Secured"
        }
    } catch {}
}

# Challenge 17: Guest Account (Should be Disabled) - WORKING
function Check-GuestDisabled {
    try {
        # We check the status of the built-in Guest account.
        # If Enabled is False, they fixed it.
        $Guest = Get-ADUser -Identity "Guest"
        
        if ($Guest.Enabled -eq $false) {
            Submit-Solve -ChallengeID 17 -ChallengeName "Guest Account Disabled"
        }
    } catch {}
}

# Challenge 18: Bad Users Deleted - WORKING
function Check-BadUsers {
    # List of accounts that must be DELETED
    # (Guest is excluded here because it should be Disabled, not deleted)
    $BadUsers = @("Support", "Temp_Admin", "krbtgt_support", "HealthMailbox01")
    
    $DetectedBadUsers = 0

    foreach ($Name in $BadUsers) {
        try {
            # Try to find the user. If we find them, the vulnerability still exists.
            $User = Get-ADUser -Identity $Name -ErrorAction Stop
            $DetectedBadUsers++
        }
        catch {
            # If Get-ADUser throws an error, it means the user is gone (Fixed).
            # We want this to happen for all users in the list.
        }
    }

    # If count is 0, it means none of the bad users exist anymore.
    if ($DetectedBadUsers -eq 0) {
        Submit-Solve -ChallengeID 18 -ChallengeName "Bad Accounts Deleted"
    }
}

# Challenge 19: Bad Groups Deleted - WORKING
function Check-BadGroups {
    # List of groups that must be DELETED
    $BadGroups = @("Helpdesk Tier 1", "Legacy Printers", "Contractors")
    
    $DetectedBadGroups = 0

    foreach ($Group in $BadGroups) {
        try {
            # Try to find the group. If we find it, the vulnerability still exists.
            $Target = Get-ADGroup -Identity $Group -ErrorAction Stop
            $DetectedBadGroups++
        }
        catch {
            # If Get-ADGroup throws an error, it means the group is gone (Fixed).
            # We want this to happen for all groups in the list.
        }
    }

    # If count is 0, it means none of the bad groups exist anymore.
    if ($DetectedBadGroups -eq 0) {
        Submit-Solve -ChallengeID 19 -ChallengeName "Bad Groups Deleted"
    }
}

# Challenge 20: Bad DNS Forwarder Removed - WORKING
function Check-DNSForwarder {
    try {
        # Get current forwarders
        $Forwarders = (Get-DnsServerForwarder -ErrorAction SilentlyContinue).IPAddress
        
        # We check if the BAD IP (10.99.99.99) is NO LONGER in the list.
        # If the list is empty or does not contain the bad IP, they fixed it.
        if ($Forwarders -notcontains "10.99.99.99") {
            Submit-Solve -ChallengeID 20 -ChallengeName "Bad DNS Forwarder Removed"
        }
    } catch {}
}

# Challenge 21: Frances fucked up CTFd

# Challenge 22: DNS Zone Transfers (Should be Restricted) - WORKING
function Check-ZoneTransfer {
    $ZoneName = "osec.local"
    try {
        # We get the zone configuration.
        $Zone = Get-DnsServerZone -Name $ZoneName -ErrorAction Stop

        # The Vulnerability is "TransferAnyServer".
        # If it is set to anything else (NoTransfer or TransferSecure), they fixed it.
        if ($Zone.SecureSecondaries -ne "TransferAnyServer") {
            Submit-Solve -ChallengeID 22 -ChallengeName "Zone Transfers Secured"
        }
    } catch {}
}

# Challenge 23: DHCP Scope Options (Bad Router) - WORKING
function Check-DHCPScope {
    $TargetScope = "10.0.0.0"
    
    try {
        # 1. Check if the scope still exists.
        # If they deleted the entire "BadScope", that counts as a fix.
        $ScopeExists = Get-DhcpServerv4Scope -ScopeId $TargetScope -ErrorAction SilentlyContinue
        if (-not $ScopeExists) {
            Submit-Solve -ChallengeID 23 -ChallengeName "DHCP Scope Fixed"
            return
        }

        # 2. If scope exists, check the Router Option (Option ID 3).
        $RouterOption = Get-DhcpServerv4OptionValue -ScopeId $TargetScope -OptionId 3 -ErrorAction SilentlyContinue
        
        # The misconfig is "10.0.0.254".
        # If the value is different (e.g., 10.0.0.1) OR if the option was deleted, they pass.
        if ($RouterOption.Value -ne "10.0.0.254") {
            Submit-Solve -ChallengeID 23 -ChallengeName "DHCP Scope Fixed"
        }
    } catch {}
}

# Challenge 24: IIS Directory Browsing (Should be Disabled) - WORKING
function Check-DirectoryBrowsing {
    try {
        # We use the IIS administration command to check the effective setting.
        # This works even if they delete the web.config line (defaults to False).
        $Property = Get-WebConfigurationProperty -Filter //directoryBrowse -PSPath 'IIS:\Sites\Default Web Site' -Name enabled -ErrorAction Stop
        
        # If enabled is False, they fixed it.
        if ($Property.Value -eq $False) {
            Submit-Solve -ChallengeID 24 -ChallengeName "Directory Browsing Disabled"
        }
    } catch {}
}

# Challenge 25: IIS App Pool Identity (Should NOT be LocalSystem) - WORKING
function Check-AppPoolIdentity {
    try {
        # Ensure the module is loaded so we can check IIS settings
        Import-Module WebAdministration -ErrorAction SilentlyContinue

        # Get the IdentityType. 
        # 0 = LocalSystem (Vulnerable)
        # 2 = NetworkService (Acceptable)
        # 4 = ApplicationPoolIdentity (Secure/Default)
        $Identity = Get-ItemProperty -Path 'IIS:\AppPools\DefaultAppPool' -Name 'processModel.identityType'

        $Val = ($Identity).ToString()
        
        # If the value is NOT 0, they have moved away from LocalSystem.
        if ($Val -ne "LocalSystem") {
            Submit-Solve -ChallengeID 25 -ChallengeName "App Pool Secured"
        }
    } catch {}
}

# Challenge 26: Remove ASP.NET 3.5 - WILL NOT WORK


# Challenge 27: IIS Basic Authentication - WILL NOT WORK

# Challenge 29: Clippy
function Check-Clippy {
    # Try to find the process
    $clippyProcess = Get-Process "SystemColorMgr" -ErrorAction SilentlyContinue
    
    # If the process is NOT found ($null), the malware is gone.
    if (-not $clippyProcess) {
        Submit-Solve -ChallengeID 29 -ChallengeName "Malware Removed"
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

#$Stopwatch.Stop()
#$Time = $Stopwatch.Elapsed
#$FormattedTime = "$($Time.Minutes):$($Time.Seconds):$($Time.Milliseconds)"
#msg * /TIME:30 "Total Execution Time: $FormattedTime"