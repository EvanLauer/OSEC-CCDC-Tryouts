# 📡 Windows Attack Beacon

**Simulated C2 Network Traffic Generator**

This directory contains the Visual Studio Solution (`.sln`) and C++ source code for the **Attack Beacon**. This lightweight binary is designed to simulate "malware beaconing" behavior on the Windows Server target. It generates outbound TCP traffic to the Attacker/C2 server, providing Blue Team candidates with network artifacts to analyze (or block) via the firewall.

## ⚙️ Functionality

The beacon is a native C++ application using the **Winsock2** library. When executed, it performs the following handshake:

1.  **Initialize:** Starts up Winsock.
2.  **Connect:** Establishes a TCP connection to the hardcoded C2 IP (Default: `192.168.103.248`) on **Port 443**.
3.  **Transmit:** Sends a specific "keyword" (passed as a command-line argument) to the listener.
4.  **Terminate:** Immediately closes the socket and exits.

*This behavior mimics a simple "heartbeat" or "command request" found in basic botnets.*

## 📂 Project Structure

* **`AttackBeacon.sln`**: The Visual Studio 2019/2022 Solution file.
* **`main.cpp`**: The source code containing the connection logic and IP configuration.
* **`Release/`**: (After building) Contains the compiled `AttackBeacon.exe`.

---

## 🛠 Configuration & Compilation

The destination IP address is hardcoded in the source to ensure it persists even if the Blue Team modifies system hosts files or DNS. To change the C2 destination:

### 1. Open the Project
Open `AttackBeacon.sln` in **Visual Studio** (Community or Enterprise).

### 2. Edit the IP
Open `main.cpp` and locate the configuration block at the top.

`const char* KALI_IP = "192.168.103.248";`

### 3. Build

    Set the build configuration to Release (x64 or x86).

    Click Build -> Build Solution (Ctrl+Shift+B).

## 🚀 Usage / Deployment

In the provided CCDC VM images, this binary is placed in C:\Scoring and triggered via **Windows Task Scheduler** to run at random intervals.

## 🛡️ Blue Team Analysis

For training purposes, this tool provides several indicators for defenders to find:

1.  **Network:** Regular outbound connections to a suspicious IP on port 443 (but not SSL/TLS traffic).
2.  **Host:** Persistence mechanisms (Scheduled Tasks) executing a binary from a non-standard location.

---

## ⚠️ Disclaimer

**For Educational Use Only.**
