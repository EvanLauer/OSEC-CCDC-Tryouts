# 🚩 CTFd Scoring Server

**Central Scoring & Dashboard**

This directory contains the instructions for setting up the central CTFd server. This server acts as the dashboard for the Blue Teams to view their score and is the destination for all telemetry sent by the scoring engines running on the target VMs.

---

## 🚀 Deployment Guide

### 1. Deploy CTFd
Deploy a standard instance of CTFd (Docker recommended).
* Ensure the server is reachable by all target VMs (Windows, Ubuntu, pfSense) on the network.
* **Default Port:** 8000 (or 80/443 if configured with a reverse proxy).

### 2. Create Challenges (Misconfigurations)
You must manually create a "Standard" challenge in CTFd for every misconfiguration being scored.

* **Mapping IDs:** You **must** reference the scoring engine scripts (e.g., `WinScoringEngine.ps1`, `LinScoringEngine.py`, `pfSenseScoringEngine.sh`) to determine the correct **Challenge ID** for each misconfiguration.
* **Flag Format:** The scoring engines use the API to mark challenges as solved; the actual flag text can be anything (e.g., `correct_config`).
* **Value:** Assign point values based on difficulty.

### 3. Create Users
Create a User account for every Proxmox user participating in the event.
* **Credentials:** Not needed as users will not be logging in to CTFd, you will simply see their challenge solves on the dashboard.

### 4. API Configuration
* Once users are created, generate an **Admin API Token** (or individual user tokens if using a push-based model) and update the `API_KEY` or `AUTH_TOKEN` variables in the scoring engine scripts on the target VMs.

---

## ⚠️ Disclaimer

**For Educational Use Only.**
