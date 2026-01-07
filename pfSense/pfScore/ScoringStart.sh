#!/bin/sh

# --- CONFIGURATION ---
# pfSense uses /root as the home directory for the admin/root user
SCORING_DIR="/root/scoring"
ENGINE_SCRIPT_SRC="./pfSenseScoringEngine.sh"
ENGINE_SCRIPT_DEST="$SCORING_DIR/pfSenseScoringEngine.sh"
TEAM_ID_FILE="$SCORING_DIR/TeamID.txt"

# 1. Prompt for Team ID
echo "========================================"
echo "   PFSENSE SCORING ENGINE SETUP"
echo "========================================"
# 'read -p' doesn't work in sh, so we use echo first
echo "Enter your Team ID:"
read INPUT_ID

# 2. Save Team ID
echo "$INPUT_ID" > "$TEAM_ID_FILE"
echo "Team ID saved."

# 3. Setup Cronjob (System-wide /etc/crontab method)
# syntax: minute hour mday month wday user command
echo "Scheduling background task..."
CRON_LINE="*	*	*	*	*	root	$ENGINE_SCRIPT_DEST"

# Check if job exists in /etc/crontab to avoid duplicates
# We use grep -q for 'quiet' check
if grep -q "PfSenseScoringEngine.sh" /etc/crontab; then
    echo "Cron job already exists. Skipping add."
else
    # Append to the system crontab
    # We add a newline before just in case the file doesn't end with one
    echo "" >> /etc/crontab
    echo "$CRON_LINE" >> /etc/crontab
    
    # Restart Cron to apply changes (FreeBSD specific command)
    /etc/rc.d/cron restart
    echo "Cron service restarted."
fi

echo ""
echo "Success! Scoring engine is active."
