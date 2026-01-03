import subprocess
import sys

# --- CONFIGURATION ---
SOURCE_VM_ID = 201      # MUST BE A TEMPLATE
START_INDEX = 2         # user02
END_INDEX = 51          # user51
TARGET_ID_BASE = 400    # user02 -> 402
NAME_PREFIX = "WinServ2016-user"
TARGET_STORAGE = "vmdata" 

# CLONE TYPE: 
# Empty string = Linked Clone
CLONE_MODE = "" 

def run_cmd(cmd):
    try:
        print(f"[*] Cloning {cmd}...")
        # Linked clones are so fast we usually don't need to wait long
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: {e}")

print(f"[*] Creating Linked Clones from Template {SOURCE_VM_ID}...")

for i in range(START_INDEX, END_INDEX + 1):
    new_vmid = TARGET_ID_BASE + i
    new_name = f"{NAME_PREFIX}{i:02d}"
    
    # Command for Linked Clone
    cmd = f"qm clone {SOURCE_VM_ID} {new_vmid} --name {new_name} --storage {TARGET_STORAGE} {CLONE_MODE}"
    
    run_cmd(cmd)

print("[+] Done.")