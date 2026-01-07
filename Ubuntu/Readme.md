# 🐧 Ubuntu Server Environment

This directory contains the source code, scoring logic, and emulation scripts for the Ubuntu Linux target.

## 📂 Directory Contents

| File/Folder | Description |
| :--- | :--- |
| **`AttackBeacon.py`** | Python scripts and configuration for the network beacon/callbacks. |
| **`UbScore/`** | Contains the scoring engine logic (`UbuntuScoringEngine.sh` and `ScoringStart.sh`). |
| **`Ubuntu Misconfigs.txt`** | A reference list of the specific vulnerabilities injected into this image. |
| **`AttackBeacon.py`** | Python file for the network beacon. |
| **`Readme.md`** | This file. |

---

## 🚀 Deployment Guide

[Download image here](https://drive.google.com/file/d/1kkC0PG3fKNoc0tT2q0jbqvxmneyH17ng/view?usp=drive_link)
 
### 1. Import the VM
Import the provided `.vma.zst` (Proxmox Backup) file into your hypervisor.
* **Credentials:** `administrator` / `Password123` (or `root` access via sudo)

### 2. Configure the Beacon (Optional)
The `AttackBeacon.py` default to calling home to **192.168.103.248**.
* If your Kali IP is different, open the Python script in, update the `C2_IP` variable, and save.

### 3. Configure the Scoring Engine
UbuntuScoringEngine.sh is configured to call to **192.168.103.243**.
* If your CTFd IP is different, just open the bash script and update 'API_URL' on line 9.

### 4. Start the Simulation
On the machine (via SSH or Console), locate and run the **`ScoringStart.sh`** script as root.

**What this script does:**
1.  Installs the Crontab entries to run the engine every minute.
2.  Installs Crontab/Systemd entries to run the Attack Beacon.

---

## 🏆 Scoring Engine

The scoring engine runs invisibly in the background via Cron.

* **Location:** `/opt/scoring/` (Out of scope for competitors/students).
* **Frequency:** Every 1 minute.
* **Reporting:** Sends data to the CTFd API.
* **Metric:** Configuration Scoring (e.g., Sudoers permissions, SSH config, Firewall rules).

---

## ⚠️ Disclaimer

**For Educational Use Only.**
