# ☁️ Proxmox Automation Scripts

**Mass Deployment & User Assignment Tools**

This directory contains Python automation scripts designed to streamline the deployment of the CCDC Tryout Environment. These tools allow administrators to rapidly provision dozens of identical VM environments for large tryout groups and automatically handle permission assignments.

## 📂 Directory Contents

| File | Description |
| :--- | :--- |
| **`VM-Clone.py`** | Mass-cloning script to generate student environments from a master template. |
| **`VM-User-Assign.py`** | Permission management script to map specific Proxmox users to their assigned VMs. |
| **`userCreate.sh`** | Creates as many users as you want in the format 'userXX'. |

---

## 🐑 VM-Clone.py

**Role:** Mass Provisioning

This script automates the tedious process of cloning the master image for every participant. Instead of manually cloning the template 20 times, this script iterates through a specified range to create unique instances for each user.

### Features
* **Bulk Creation:** automatically generates **20 copies** of the specified source VM (template).
* **Sequential ID Assignment:** Creates VMs in a contiguous ID range (e.g., `602`, `603`, `604`... `621`).
* **Efficiency:** Uses Proxmox linked clones (if configured) for rapid deployment and low disk usage.

**Usage:**
Edit the script to define your Source Template ID and the Starting Target ID, then run:
```bash
python3 VM-Clone.py
```

---

## 🔐 VM-User-Assign.py

**Role:** Access Control / Permissions

Once the VMs are created, this script secures the environment by ensuring candidates can only access their specific machine. It programmatically iterates through the user list and VM list to create a 1:1 mapping.

### Logic
* **Pattern Matching:** It maps User IDs to VM IDs based on the suffix.
    * `user02` is granted access to **VM 602**.
    * `user03` is granted access to **VM 603**.
    * ...and so on.
* **Security:** Prevents students from accidentally (or intentionally) messing with another candidate's tryout environment.

**Usage:**
Run this script immediately after `VM-Clone.py` completes:
```bash
python3 VM-User-Assign.py
```

---

## 🐑 userCreate.sh

**Role:** Mass Creating Users

This script automates the tedious process of creating a user for every participant. Instead of manually creating 20 users, this script iterates through a specified range to create unique instances for each user.

### Features
* **Bulk Creation:** automatically generates 20 users of the specified user range (eg. user05 - user50).
* **Login Export:** exports the usernames and passwords for all generated users to logins.txt.

**Usage:**
Edit the script to make as many users as you want, then run:
```bash
./userCreate.sh
```

---

## ⚠️ Disclaimer

**Admin Access Required.**
These scripts interact directly with the Proxmox API/CLI. Ensure you have appropriate administrative privileges on the cluster before executing them. Misuse could result in overwritten VMs or messed up permission tables.
