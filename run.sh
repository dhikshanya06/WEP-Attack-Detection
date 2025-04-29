#! /bin/bash
clear

# Kill the process that is holding the lock if necessary
sudo kill -9 77284

# Install the required libraries for packet capture (pcap) and curl for sending WhatsApp alerts

echo

# Compile the C program with curl and pcap library linking
# Replace "new.c" with the actual name of your C file containing the alert code
sudo gcc -o alertprg new.c -lcurl -lpcap
if [ $? -eq 0 ]; then
    echo "Compilation successful."
else
    echo "Compilation failed."
    exit 1
fi

# Run the compiled program with the specified input and output paths
# Update the pcap file and output log file paths accordingly
sudo ./alertprg "/home/pradheeba/home/scp/new_input.pcap" "/home/pradheeba/home/scp/output_log.txt"
if [ $? -eq 0 ]; then
    echo "Program executed successfully."
else
    echo "Program execution failed."
    exit 1
fi

# Optionally remove the compiled program if not needed
# sudo rm alertprg
