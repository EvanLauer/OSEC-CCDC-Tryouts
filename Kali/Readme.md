# 🐉 Kali C2 & Attack Server

**Central Command & Control Listener**

This directory contains the Python-based C2 server (`attacker.py`) used to control the victim machines. It acts as the "Puppet Master" for the simulation, listening for callbacks from the Windows and Ubuntu beacons and issuing commands to trigger annoyance payloads.

## 📂 Directory Contents

| File | Description |
| :--- | :--- |
| **`attacker.py`** | The main multi-threaded listener and attack logic script. |
| **`README.md`** | This file. |

---

## 🛠️ Setup & Prerequisites

**Before running the attacker script, you must manually prepare the following dependencies in this folder:**

1.  **Create the Ransom Note:**
    Create a file named `ransom.txt` in this directory. Add whatever scary text you want the victim to see.

2.  **Download the Goose:**
    * **Download:** [Desktop Goose by Sam Person](https://samperson.itch.io/desktop-goose)
    * **Action:** Download the ZIP file, rename it to **`Goose.zip`**, and place it in this directory.

3.  **Install System Dependencies:**
    The script relies on `impacket` and `paramiko`.
    ```bash
    sudo apt install python3-paramiko python3-impacket impacket-scripts
    ```

---

## ⚙️ How It Works

The `attacker.py` script is a **multi-threaded TCP server** designed to handle high-volume traffic from multiple student environments simultaneously.

1.  **The Listener:** Binds to **Port 8080** (redirected from 443 via firewall rules) and waits for incoming TCP connections.
2.  **The Worker Pool:** Uses a queue system with **10 concurrent worker threads**. This ensures that if one student's machine is slow to respond, it doesn't block attacks against other students.
3.  **Authentication:**
    * **Windows:** Uses `impacket-psexec` with known credentials (`OSEC/j.davis`).
    * **Linux:** Uses `paramiko` (SSH) to login as `guest_account` with an empty password (a deliberate misconfiguration).
4.  **Payload Delivery:** Depending on the "keyword" sent by the victim's beacon, the server selects the corresponding attack function (`goodbye`, `ransom`, `HONK`, etc.) and executes it remotely.

---

## 🪟 Windows Attack Modules

These attacks use SMB and RPC to disrupt the user's workflow.

### 1. 👋 Goodbye Chat
* **Keyword:** `goodbye`
* **Behavior:** Sends a Windows Message Popup (`msg *`) saying "Goodbye Chat!", then immediately executes `tsdiscon console`.
* **Impact:** Kicks the user out of their RDP/Console session, forcing them to log back in.

### 2. 💸 Ransom-Scare
* **Keyword:** `ransom`
* **Behavior:** Uploads your local `ransom.txt` directly to the Administrator's Desktop.
* **Impact:** Simulates a ransomware note drop to panic the user (Social Engineering).

### 3. 🪿 HONK (The Goose)
* **Keyword:** `HONK`
* **Behavior:**
    1.  Uploads `Goose.zip` to `C:\Windows\Temp`.
    2.  Uses PowerShell to unzip the archive.
    3.  Sends a popup message: **"HONK"**.
    4.  Queries the terminal services to find the `Administrator` session ID and forces a **Logoff** command.
* **Impact:** Forces a reboot/re-login cycle where the "Desktop Goose" annoyance software will likely start up (if persistence was pre-set), creating ongoing visual distractions.

---

## 🐧 Ubuntu Attack Modules

These attacks leverage SSH and Sudo misconfigurations to clutter the system.

### 1. 🗑️ The Litterbug
* **Keyword:** `litter`
* **Behavior:** SSHs in and runs a loop to `touch` 50 empty text files inside `/opt/service`.
* **Impact:** Exploits world-writable directory permissions to clutter critical service folders.

### 2. 🧟 Zombie Swarm
* **Keyword:** `zombie`
* **Behavior:** Copies `/bin/sleep` to a temporary file named `/tmp/VIRUS_SCANNING`, then spawns 50 background instances of it.
* **Impact:** Floods the process table, making it difficult to use tools like `top` or `htop` to find real malicious processes.

### 3. 📢 Wall of Shame
* **Keyword:** `shame`
* **Behavior:** Exploits a NOPASSWD sudoer misconfiguration. It runs a background loop that pipes a warning message into the `wall` command every 45 seconds.
* **Impact:** Spams every open terminal window with "SECURITY ALERT: Guest Account has ROOT access," interrupting command-line work.

---

## 🚀 Usage

On the Kali Linux machine:

```bash
# 1. Verify dependencies exist (create ransom.txt and download Goose.zip first!)
ls -l attacker.py ransom.txt Goose.zip

# 2. Run the listener (Root permissions likely required for binding ports)
sudo python3 attacker.py
```

*The script will print "BATTLESTATION ONLINE" and wait for incoming beacons.*

---

## ⚠️ Disclaimer

**For Educational Use Only.**
This tool performs active exploitation (SSH brute force, SMB exec, process flooding). It is designed strictly for the authorized CCDC Tryout Environment. Do not use against targets you do not own.
