#!/bin/bash

# --- CONFIGURATION ---
# We use /opt/scoring for the backend files (hidden from user view)
SCORING_DIR="/home/administrator/scoring"
ENGINE_SCRIPT_DEST="$SCORING_DIR/UbuntuScoringEngine.sh"
TEAM_ID_FILE="$SCORING_DIR/TeamID.txt"

# 1. Check for Sudo/Root
if [ "$EUID" -ne 0 ]; then
	echo "Please run as root."
	echo "Usage: sudo ./ScoringStart.sh"
	exit
fi

# 2. Prompt for Team ID
echo "============================="
echo " UBUNTU SCORING ENGINE SETUP "
echo "============================="
read -p "Enter your User ID: " INPUT_ID

# 3. Save Team ID
echo "$INPUT_ID" > "$TEAM_ID_FILE"
echo "Team ID saved."

# 4. Setup Cronjob

echo "Scheduling background task..."
CRON_JOB="* * * * * $ENGINE_SCRIPT_DEST"

(crontab -l 2>/dev/null | grep -Fv "$ENGINE_SCRIPT_DEST"; echo "$CRON_JOB") | crontab -

echo ""
echo "Success! Scoring engine is active."
