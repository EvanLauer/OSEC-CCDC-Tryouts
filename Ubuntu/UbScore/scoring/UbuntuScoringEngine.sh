#!/bin/bash

# ==========================================
# OSEC CCDC TRYOUT UBUNTU SCORING ENGINE
# ==========================================

# --- 1. CONFIGURATION ---
ADMIN_TOKEN="ctfd_4eff9761c0331fef0eafee7500b628e50b5fdcec903d74f3d97832d299a7faed"
API_URL="http://192.168.103.243:4000/api/v1/submissions"
TEAM_ID_FILE="/home/administrator/scoring/TeamID.txt"
LOCK_DIR="/home/administrator/scoring/checks"

# Ensure Lock Directory Exists
mkdir -p "$LOCK_DIR"

# --- 2. HELPER FUNCTION ---
submit_solve() {
    local CHALLENGE_ID=$1
    local CHALLENGE_NAME=$2

    # Safety Check: If Team ID file doesn't exist, stop.
    if [ ! -f "$TEAM_ID_FILE" ]; then
        return
    fi

    # Read Team ID (trimming whitespace)
    local TEAM_ID=$(cat "$TEAM_ID_FILE" | xargs)

    # Prepare JSON Data
    JSON_DATA=$(cat <<EOF
{
    "challenge_id": $CHALLENGE_ID,
    "user_id": $TEAM_ID,
    "type": "correct",
    "provided": "Scripted"
}
EOF
)

    # Send Request using Curl
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$API_URL" \
        -H "Authorization: Token $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$JSON_DATA")

    # Check result
    # 200 = OK (Success)
    if [ "$HTTP_STATUS" -eq 200 ]; then
        
        # 1. CREATE LOCKFILE (Prevents check from running again)
        touch "$LOCK_DIR/${CHALLENGE_ID}.lock"
        
        # 2. Notify User
        echo "CORRECT! $CHALLENGE_NAME Fixed. Points Awarded." | wall
    
    elif [ "$HTTP_STATUS" -eq 400 ]; then
        # Silent fail for "Already Solved" or "Rate Limited"
        :
    else
        # Optional: Debug specific errors
        :
    fi
}

# --- 3. CHECK FUNCTIONS ---

# Challenge 0: Test 
check_test() {
    local ID=28
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

	submit_solve $ID "Test"
}

check_writable_crontab() {
    local ID=30
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    # Misconfig: chmod 777 /etc/crontab -> Fix: chmod 644
    if [ -f /etc/crontab ]; then
        local perms=$(stat -c "%a" /etc/crontab)
        if [ "$perms" == "644" ]; then
            submit_solve $ID "World-Writable Crontab"
        fi
    fi
}

check_exposed_shadow() {
    local ID=31
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    # Misconfig: chmod 644 -> Fix: chmod 640 or 600
    local target="/etc/shadow"
    if [ -f "$target" ]; then
        local perms=$(stat -c "%a" "$target")
        if [ "$perms" == "640" ] || [ "$perms" == "600" ]; then
            submit_solve $ID "Shadow File Exposure Fixed"
        fi
    fi
}

check_exposed_history() {
    local ID=32
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    # Misconfig: chmod 644 -> Fix: chmod 600
    local target_file="/home/administrator/.bash_history"
    if [ -f "$target_file" ]; then
        local perms=$(stat -c "%a" "$target_file")
        if [ "$perms" == "600" ]; then
            submit_solve $ID "History File Exposure Fixed"
        fi
    fi
}

check_root_equivalency() {
    local ID=33
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    # Check if 'sysadmin' is removed OR stripped of UID 0
    local passwd_file="/etc/passwd"
    if ! grep -q "^sysadmin:" "$passwd_file"; then
        local root_uid_count=$(awk -F: '($3 == "0") {print $1}' "$passwd_file" | wc -l | xargs)
        if [ "$root_uid_count" -eq 1 ]; then
            submit_solve $ID "Root-Equivalency Backdoor Removed"
        fi
    fi
}

check_log_tampering() {
    local ID=34
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    if [ -f /etc/login.defs ]; then
        local check1=$(grep -i "^FAILLOG_ENAB" /etc/login.defs | awk '{print $2}' | tr -d '[:space:]')
        local check2=$(grep -i "^LOG_UNKFAIL_ENAB" /etc/login.defs | awk '{print $2}' | tr -d '[:space:]')
        if [[ "$check1" == "yes" ]] && [[ "$check2" == "yes" ]]; then
            submit_solve $ID "Log Tampering Fix"
        fi
    fi
}

check_suid_nano() {
    local ID=35
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    if [ -f /usr/bin/nano ]; then
        local perms=$(stat -c "%a" /usr/bin/nano)
        # Check if first digit is NOT 4 (SUID bit)
        if [[ "$perms" -lt 4000 ]]; then
            submit_solve $ID "SUID Bit Removed from Nano"
        fi
    fi
}

check_world_writable_opt() {
    local ID=36
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    if [ -d /opt/service ]; then
        local perms=$(stat -c "%a" /opt/service)
        if [ "$perms" != "777" ]; then
            submit_solve $ID "Insecure App Directory Secured"
        fi
    else
        submit_solve $ID "Insecure App Directory Removed"
    fi
}

check_ssh_empty_passwords() {
    local ID=37
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    # 1. Check SSH Config
    local ssh_check=$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | awk '{print $2}' | tr -d '[:space:]')
    # 2. Check Shadow File
    local guest_pass_check=$(grep "^guest_account:" /etc/shadow | cut -d: -f2)

    if [[ "$ssh_check" != "yes" ]]; then
        if [[ -z "$guest_pass_check" ]] || [[ "$guest_pass_check" == "!" ]] || [[ "$guest_pass_check" == "*" ]]; then
            if ! grep -q "^guest_account:" /etc/passwd; then
                submit_solve $ID "SSH Empty Password Access Fixed"
            elif [[ "$guest_pass_check" != "" ]]; then
                 submit_solve $ID "SSH Empty Password Access Fixed"
            fi
        fi
    fi
}

check_stealth_binary() {
    local ID=38
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    if [ ! -f /usr/bin/.sys_diagnostic ]; then
        submit_solve $ID "Stealth SUID Binary Removed"
    fi
}

check_ssh_banner() {
    local ID=39
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    if ! grep -iq "^Banner" /etc/ssh/sshd_config; then
        submit_solve $ID "Information Disclosure Banner Removed"
        return
    fi
    if [ -f /etc/issue.net ]; then
        if ! grep -iq "Ubuntu" /etc/issue.net; then
            submit_solve $ID "Information Disclosure Banner Removed"
        fi
    fi
}

check_ipv4_forwarding() {
    local ID=40
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    local running_state=$(sysctl -n net.ipv4.ip_forward)
    if [[ "$running_state" == "0" ]]; then
        if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
            submit_solve $ID "IPv4 Forwarding Disabled"
        fi
    fi
}

check_icmp_redirects() {
    local ID=41
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    local running_state=$(sysctl -n net.ipv4.conf.all.accept_redirects)
    if [[ "$running_state" == "0" ]]; then
        if ! grep -q "net.ipv4.conf.all.accept_redirects=1" /etc/sysctl.conf; then
            submit_solve $ID "ICMP Redirects Disabled"
        fi
    fi
}

check_etc_perms() {
    local ID=42
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    if [ -f /etc/environment ]; then
        local perms=$(stat -c "%a" /etc/environment)
        if [ "$perms" != "777" ]; then
            submit_solve $ID "System Environment File Secured"
        fi
    fi
}

check_syslog_blackhole() {
    local ID=43
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    if [ -e /var/log/syslog ]; then
        if [ ! -L /var/log/syslog ]; then
            submit_solve $ID "System Logging Restored"
        fi
    fi
}

check_backdoor() {
    local ID=44
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    if [ ! -f /etc/sudoers.d/backdoor ]; then
        submit_solve $ID "Sudoers Backdoor Removed"
    fi
}

check_persistence() {
    local ID=45
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    if [ ! -f /etc/cron.d/.sys_sync ]; then
        local shadow_perms=$(stat -c "%a" /etc/shadow)
        if [ "$shadow_perms" != "777" ]; then
            submit_solve $ID "Hidden Cron and Shadow Permissions Fixed"
        fi
    fi
}

check_motd() {
    local ID=46
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    if ! grep -q "chmod 777 /etc/shadow" /etc/update-motd.d/00-header; then
        local shadow_perms=$(stat -c "%a" /etc/shadow)
        if [ "$shadow_perms" != "777" ]; then
            submit_solve $ID "MotD Injection Cleaned"
        fi
    fi
}

check_pw_policy() {
    local ID=47
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    local pam_file="/etc/pam.d/common-password"
    if ! grep -q "minlen=1" "$pam_file"; then
        if grep -qE "obscure|minlen=[8-9]|minlen=[0-9]{2,}" "$pam_file"; then
            submit_solve $ID "Password Policy Hardened"
        fi
    fi
}

# --- 4. EXECUTE ---

#check_test
check_writable_crontab
check_exposed_shadow
check_exposed_history
check_root_equivalency
check_log_tampering
check_suid_nano
check_world_writable_opt
check_ssh_empty_passwords
check_stealth_binary
check_ssh_banner
check_ipv4_forwarding
check_icmp_redirects
check_etc_perms
check_syslog_blackhole
check_backdoor
check_persistence
check_motd
check_pw_policy