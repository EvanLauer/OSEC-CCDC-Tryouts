# 🛡️ pfSense Firewall Environment

This directory contains the source code, scoring logic, and configuration files for the pfSense target. In the CCDC scenario, this machine acts as the primary network gateway and firewall, making it a critical choke point for the Blue Team to secure.

## 📂 Directory Contents

| File/Folder | Description |
| :--- | :--- |
| **`pfScore/`** | Directory containing the scoring engine logic and startup scripts. |
| **`pfSense Misconfigs.txt`** | A reference list of the specific vulnerabilities injected into this image. |
| **`Readme.md`** | This file. |

---

## 🚀 Deployment Guide

[Download image here](https://drive.google.com/file/d/19CO-sNEtVIqQk3_8Ga3QPyFcV7LvQLl0/view?usp=sharing)

### 1. Import the VM
Import the provided `.vma.zst` (Proxmox Backup) file into your hypervisor.
* **Web Credentials:** `admin` / `pfsense` (Default) or `Password123`
* **SSH Credentials:** `root` / `pfsense` (or `Password123`)

### 2. Configure the Scoring Engine
The `pfSenseScoringEngine.sh` script is configured to call the scoring server at **192.168.103.243**.
* **File Location:** `pfScore/scoring/pfSenseScoringEngine.sh`
* **Action:** If your CTFd IP is different, open the bash script and update the `API_URL` variable.

### 3. Start the Simulation
On the machine (via SSH or Console Option 8 "Shell"), locate and run the **`ScoringStart.sh`** script as root.

**What this script does:**
1.  Installs the Crontab entries to run the engine every minute.
2.  Ensures required packages (like `curl` or `bash`) are available if needed.

---

## 🏆 Scoring Engine

The scoring engine runs invisibly in the background via Cron.

* **Location:** `/root/scoring/` (Typical deployment location).
* **Frequency:** Every 1 minute.
* **Reporting:** Sends data to the CTFd API.
* **Metric:** Configuration Scoring (e.g., Firewall Rules, Alias configurations, User accounts, Open ports).

---

## ⚠️ Disclaimer

**For Educational Use Only.**
