# 🪟 Windows Server Environment

**Primary Domain Controller & File Server**

This directory contains the source code, scoring logic, and emulation binaries for the Windows Server 2016 target. In the CCDC scenario, this machine acts as the primary Domain Controller (DC) and critical file share host, making it a high-value target for the Blue Team to secure.

## 📂 Directory Contents

| File/Folder | Description |
| :--- | :--- |
| **`AttackBeacon/`** | Visual Studio Solution (`.sln`) and source code for the network beacon. |
| **`WinScore/`** | Contains the scoring engine logic (`WinScoringEngine.ps1`). |
| **`CCDC Win Misconfigs.txt`** | A reference list of the specific vulnerabilities injected into this image. |
| **`SystemColorMgr.exe`** | The compiled "Evil Clippy" desktop annoyance tool. |
| **`Readme`** | This file. |

---

## 🚀 Deployment Guide

### 1. Import the VM
Import the provided `.vma.zst` file into your hypervisor.
* **Credentials:** `Administrator` / `Password123`

### 2. Configure the Beacon (Optional)
The `AttackBeacon` defaults to calling home to **192.168.103.248**.
* If your Kali IP is different, open the solution in the `AttackBeacon` folder, update the IP constant, and recompile.

### 3. Start the Simulation
On the Administrator Desktop, locate and run the **`ScoringStart`** script.

**What this script does:**
1.  Creates a Scheduled Task to run the engine every minute.
2. Created Scheduled Tasks to run the Attack Beacon.
3.  Launches SystemColorMgr.exe (Evil Clippy).

---

## 🏆 Scoring Engine

The scoring engine runs invisibly in the background via Task Scheduler.

* **Location:** `C:\Scoring\` (Out of scope for competitors/students).
* **Frequency:** Every 1 minute.
* **Reporting:** Sends data to the CTFd API.
* **Metric:** Configuration Scoring (e.g., Guest account status, SMB shares, Policy checks).

---

## 📎 "Evil Clippy" (SystemColorMgr)

**Internal Name:** `SystemColorMgr.exe`
**Role:** Desktop Annoyance / Grayware

This environment includes a custom "malware" binary designed to harass the Blue Team.

* **Behavior:** Runs as a standalone executable in `System32`. It monitors active windows and interrupts the user with sarcastic popup messages and animations every few minutes.
* **Removal:** The Blue Team must identify the process and terminate it to stop the annoyances.

---

## ⚠️ Disclaimer

**For Educational Use Only.**
Do not deploy `SystemColorMgr.exe` on production machines. While harmless, it is designed to be intentionally frustrating and persistent.
