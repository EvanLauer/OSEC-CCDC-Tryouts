import subprocess
import sys

# --- CONFIGURATION ---
START_ID = 2        # user02
END_ID = 51         # user51
VM_BASE = 600       # user02 -> VM 602
REALM = "pve"       # Change to "pam" if these are Linux system users
ROLE_NAME = "TryoutRole" # Ensure this role exists before running!

def run_cmd(cmd):
    """Runs a shell command and prints the output."""
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"[+] Success: {cmd}")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed: {cmd} \nError: {e}")

print("========================================")
print(f"[*] Proxmox Permission Assigner")
print(f"[*] Users: user{START_ID:02d} - user{END_ID:02d}")
print(f"[*] Role: {ROLE_NAME} (Must already exist)")
print("========================================\n")

# ASSIGN PERMISSIONS LOOP
print(f"[*] Assigning ACLs for {END_ID - START_ID + 1} users...")

for i in range(START_ID, END_ID + 1):
    # Format user: user02, user03 ... user51
    username = f"user{i:02d}@{REALM}"
    
    # Calculate VM ID: 600 + 2 = 602
    vmid = VM_BASE + i
    
    # Construct the ACL command
    # /vms/{vmid} -> This path restricts the user to ONLY this specific VM.
    cmd = f"pveum acl modify /vms/{vmid} -user {username} -role {ROLE_NAME}"
    
    run_cmd(cmd)

print("\n[+] Assignment Complete.")