# 🛡️ CCDC Tryout & Training Environment

**A modular Blue Team defense suite designed for University of North Florida CCDC tryouts and team practice.**

This repository hosts the infrastructure, scoring logic, and emulation tools for a deployable **Blue Team** training environment. It provides a standardized scenario where candidates or team members must secure compromised systems against active misconfigurations and persistence mechanisms while maintaining critical services.

## 🎯 Project Overview

This environment is built to serve two main purposes:

1.  **CCDC Tryouts:** A quantitative method to evaluate new candidates on their ability to identify and fix security flaws under pressure.
2.  **Defensive Training:** A flexible sandbox for practicing incident response, system hardening, and service restoration.

## 💻 The Environment

The network consists of three primary Virtual Machines, each pre-seeded with intentional vulnerabilities and security flaws for the Blue Team to remediate:

* **Windows Server 2016:**
* **Ubuntu Server 24.04:**
* **pfSense 2.7.2:**

## 🏆 Scoring Engine

The environment features a custom scoring engine designed for real-time feedback and metrics:

* **Mechanism:** Scoring scripts run locally on each VM via Scheduled Tasks (Windows) or Cron jobs (Linux) every minute.
* **Logic:** The engine audits the system for the misconfigurations (e.g., "Is the guest account disabled?", "Are file permissions fixed?", "Is the firewall active?").
* **Integration:** Points are automatically reported to a central **CTFd** instance via API hooks.
* **Flexibility:** The engine is architected to easily be repurposed from *Configuration Scoring* (fixing misconfigs) to *Service Scoring* (maintaining uptime).

## 📂 Repository Contents

This repository contains all source code and tools used to deploy and manage the simulation:

* **Scoring Scripts:** Python/Bash/PowerShell scripts that audit system security.
* **Misconfiguration Lists:** Documentation of the specific vulnerabilities injected into the targets for training purposes.
* **Simulation Tools:** Automated scripts (formerly "Attacker" tools) used to generate traffic, noise, and persistence checks to test Blue Team responsiveness.
* **VM Exports:** *(Coming Soon)* Full Proxmox backup files for rapid deployment.

## 🚀 Deployment Instructions

Detailed deployment and usage instructions are split by component. Please refer to the **README.md** file located inside each specific folder for step-by-step guides on setting up that portion of the environment.

* `/Windows` - Scoring scripts, misconfigurations, and other tools for Windows.
* `/Ubuntu` - Scoring scripts and misconfigurations for Ubuntu.
* `/pfSense` - Scoring scripts and misconfigurations for pfSense.
* `/Kali` - Attack engine.
* `/Proxmox` - Deployment and scaling scripts.

---

## ⚠️ Disclaimer

**For Educational Use Only.**

This environment is designed strictly for authorized cybersecurity training and CCDC competition preparation. Do not deploy these configurations or tools on production networks.
