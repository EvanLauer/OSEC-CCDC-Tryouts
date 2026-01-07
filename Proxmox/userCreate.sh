# Define the output file
OUTPUT_FILE="logins.txt"
> "$OUTPUT_FILE"

# Loop from 2 to 21
for i in $(seq -f "%02g" 2 21); do
    USERNAME="user$i"
    
    # Generate a random 6-character alphanumeric password
    PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 8)
    
    # Create the user in the 'pve' realm (Proxmox's internal DB)
    pveum user add "${USERNAME}@pve" --password "$PASSWORD"
    
    # Append to the text file
    echo "${USERNAME}:${PASSWORD}" >> "$OUTPUT_FILE"
done

echo "Done! Credentials saved to $OUTPUT_FILE"
