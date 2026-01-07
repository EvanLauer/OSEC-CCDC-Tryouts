#!/bin/sh

# ==========================================
# OSEC CCDC TRYOUT pfSense SCORING ENGINE
# ==========================================

# --- 1. CONFIGURATION ---
ADMIN_TOKEN="ctfd_4eff9761c0331fef0eafee7500b628e50b5fdcec903d74f3d97832d299a7faed"
API_URL="http://192.168.103.243:4000/api/v1/submissions"
TEAM_ID_FILE="/root/scoring/TeamID.txt"
LOCK_DIR="/root/scoring/checks"

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

# Challenge 1: WAN Management Exposure
check_wan_management() {
    local ID=48
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_RULE_FOUND=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (is_array($conf["filter"]["rule"])) {
            foreach($conf["filter"]["rule"] as $r) {
                if (isset($r["disabled"]) == false) {
                    if (isset($r["destination"]["network"]) && $r["destination"]["network"] == "wanip") {
                        if (isset($r["destination"]["port"])) {
                            $p = $r["destination"]["port"];
                            if ($p == "80" || $p == "443" || $p == "http" || $p == "https") {
                                echo "FOUND";
                                break;
                            }
                        }
                    }
                }
            }
        }
    ')

    if [ "$BAD_RULE_FOUND" != "FOUND" ]; then
        submit_solve $ID "WAN Management Secured"
    fi
}

# Challenge 2: Floating Rule "Bypass All"
check_floating_bypass() {
    local ID=49
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_RULE_FOUND=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (is_array($conf["filter"]["rule"])) {
            foreach($conf["filter"]["rule"] as $r) {
                if (isset($r["disabled"]) == false && 
                    isset($r["floating"]) && 
                    isset($r["quick"]) && 
                    $r["type"] == "pass") {
                    if (isset($r["source"]["any"]) && isset($r["destination"]["any"])) {
                        if (isset($r["protocol"]) == false) {
                            echo "FOUND";
                            break;
                        }
                    }
                }
            }
        }
    ')

    if [ "$BAD_RULE_FOUND" != "FOUND" ]; then
        submit_solve $ID "Floating Bypass Removed"
    fi
}     

# Challenge 3: Disable Packet Filtering
check_packet_filtering() {
    local ID=50
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["system"]["disablefilter"])) {
            echo "FOUND";
        }
    ')

    if [ "$BAD_SETTING" != "FOUND" ]; then
        submit_solve $ID "Packet Filtering Re-Enabled"
    fi
}

# Challenge 4: IP Do-Not-Fragment Compatibility
check_ip_fragmentation() {
    local ID=51
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["system"]["scrubnodf"])) {
            echo "FOUND";
        }
    ')

    if [ "$BAD_SETTING" != "FOUND" ]; then
        submit_solve $ID "IP Fragmentation Fixed"
    fi
}

# Challenge 5: Admin Access Protocol Downgrade
check_admin_protocol() {
    local ID=52
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["system"]["webgui"]["protocol"]) && $conf["system"]["webgui"]["protocol"] == "http") {
            echo "FOUND";
        }
    ')

    if [ "$BAD_SETTING" != "FOUND" ]; then
        submit_solve $ID "Admin Protocol Secured (HTTPS)"
    fi
}

# Challenge 6: WebGUI Redirect Disabled - WILL NOT WORK
check_webgui_redirect() {
    local ID=53
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["system"]["webgui"]["disablehttpredirect"])) {
            echo "FOUND";
        }
    ')

    if [ "$BAD_SETTING" != "FOUND" ]; then
        submit_solve $ID "WebGUI Redirect Enabled"
    fi
}

# Challenge 7: Hardware Checksum Offloading Disabled - WILL NOT WORK
check_checksum() {
    local ID=54
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["system"]["disablechecksumoffloading"])) {
            echo "FOUND";
        }
    ')

    if [ "$BAD_SETTING" != "FOUND" ]; then
        submit_solve $ID "Checksum Offloading Enabled"
    fi
}

# Challenge 8: Unlocked Console (Physical Security)
check_console_lock() {
    local ID=55
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["system"]["disableconsolemenu"]) == false) {
            echo "VULNERABLE";
        }
    ')

    if [ "$BAD_SETTING" != "VULNERABLE" ]; then
        submit_solve $ID "Console Password Protected"
    fi
}

# Challenge 9: DNS Rebinding Checks Disabled
check_dns_rebind() {
    local ID=57
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi
    
    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["system"]["webgui"]["nodnsrebindcheck"])) {
            echo "VULNERABLE";
        }
    ')

    if [ "$BAD_SETTING" != "VULNERABLE" ]; then
        submit_solve $ID "DNS Rebinding Checks Enabled"
    fi
}

# Challenge 10: SSH Root Login (Password Auth)
check_ssh() {
    local ID=56
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["system"]["ssh"]["enable"])) {
            if (isset($conf["system"]["ssh"]["sshdkeyonly"]) == false) {
                echo "VULNERABLE";
            }
        }
    ')

    if [ "$BAD_SETTING" != "VULNERABLE" ]; then
        submit_solve $ID "SSH Password Login Disabled"
    fi
}

# Challenge 11: Bogon Networks Unblocked (Reconnaissance)
check_bogons() {
    local ID=58
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi
    
    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["interfaces"]["wan"]["blockbogons"]) == false) {
            echo "VULNERABLE";
        }
    ')

    if [ "$BAD_SETTING" != "VULNERABLE" ]; then
        submit_solve $ID "Bogon Networks Blocked"
    fi
}

# Challenge 12: Connection Optimization (DoS Vulnerability)
check_firewall_optimization() {
    local ID=59
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["system"]["optimization"]) && $conf["system"]["optimization"] == "aggressive") {
            echo "VULNERABLE";
        }
    ')

    if [ "$BAD_SETTING" != "VULNERABLE" ]; then
        submit_solve $ID "Firewall Optimization Normal"
    fi
}

# Challenge 13: Global Log Suppression (Remote Logging)
check_log_suppression() {
    local ID=60
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["syslog"]["remoteserver"]) && $conf["syslog"]["remoteserver"] != "") {
            echo "VULNERABLE";
        }
    ')

    if [ "$BAD_SETTING" != "VULNERABLE" ]; then
        submit_solve $ID "Remote Logging Disabled"
    fi
}

# Challenge 14: NAT Reflection (Pure NAT Enabled)
check_nat_reflection() {
    local ID=61
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        $vulnerable = false;
        if (isset($conf["system"]["enablenatreflectionpurenat"])) {
            $vulnerable = true;
        }
        if (isset($conf["system"]["natreflection"]) && $conf["system"]["natreflection"] == "purenat") {
            $vulnerable = true;
        }
        if ($vulnerable) {
            echo "VULNERABLE";
        }
    ')

    if [ "$BAD_SETTING" != "VULNERABLE" ]; then
        submit_solve $ID "NAT Reflection Disabled"
    fi
}

# Challenge 15: Asymmetric Routing Hole (Disable Reply-to)
check_reply() {
    local ID=62
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["system"]["disablereplyto"])) {
            echo "VULNERABLE";
        }
    ')

    if [ "$BAD_SETTING" != "VULNERABLE" ]; then
        submit_solve $ID "Reply-to Enabled"
    fi
}

# Challenge 16: Backdoor Admin User
check_user() {
    local ID=63
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_USER_FOUND=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        $target_uid = null;
        if (is_array($conf["system"]["user"])) {
            foreach ($conf["system"]["user"] as $u) {
                if ($u["name"] == "_user") {
                    $target_uid = $u["uid"];
                    break;
                }
            }
        }
        if ($target_uid !== null && is_array($conf["system"]["group"])) {
            foreach ($conf["system"]["group"] as $g) {
                if ($g["name"] == "admins" && isset($g["member"])) {
                    $members = $g["member"];
                    if (is_array($members) == false) {
                        $members = array($members);
                    }
                    if (in_array($target_uid, $members)) {
                        echo "FOUND";
                    }
                }
            }
        }
    ')

    if [ "$BAD_USER_FOUND" != "FOUND" ]; then
        submit_solve $ID "Backdoor User Removed"
    fi
}

# Challenge 17: SNMP Leak (Default Community String)
check_snmp() {
    local ID=64
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_SETTING=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (isset($conf["snmpd"]["enable"]) && 
            isset($conf["snmpd"]["rocommunity"]) && 
            $conf["snmpd"]["rocommunity"] == "public") {
            echo "VULNERABLE";
        }
    ')

    if [ "$BAD_SETTING" != "VULNERABLE" ]; then
        submit_solve $ID "SNMP Secured"
    fi
}

# Challenge 18: Weak Admin Password
check_password() {
    local ID=65
    if [ -f "$LOCK_DIR/${ID}.lock" ]; then return; fi

    BAD_PASSWORD=$(php -r '
        require("config.inc");
        $conf = parse_config(true);
        if (is_array($conf["system"]["user"])) {
            foreach ($conf["system"]["user"] as $u) {
                if ($u["name"] == "admin") {
                    if (password_verify("Password123", $u["bcrypt-hash"])) {
                        echo "VULNERABLE";
                    }
                }
            }
        }
    ')

    if [ "$BAD_PASSWORD" != "VULNERABLE" ]; then
        submit_solve $ID "Admin Password Changed"
    fi
}

# --- 4. EXECUTE ---

# Call your checks here
#check_test
check_wan_management
check_floating_bypass
check_packet_filtering
check_ip_fragmentation
check_admin_protocol
#check_webgui_redirect
#check_checksum
check_console_lock
check_dns_rebind
check_ssh
check_bogons
check_firewall_optimization
check_log_suppression
check_nat_reflection
check_reply
check_user
check_snmp
check_password