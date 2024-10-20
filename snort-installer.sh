#!/bin/bash

echo "Checking for system updates..."
sudo apt update && sudo apt upgrade -y

echo "Installing required packages..."
sudo apt install -y snort libpcap-dev libdumbnet-dev zlib1g-dev

SNORT_DIR="/etc/snort/rules"
if [ ! -d "$SNORT_DIR" ]; then
    echo "Snort directory not found. Please ensure Snort is installed."
    exit 1
fi

echo "Backing up the configuration file..."
sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.bak

echo "Configuring the Snort configuration file..."
sudo bash -c "echo 'var HOME_NET 192.168.1.0/24' > /etc/snort/snort.conf"
sudo bash -c "echo 'var EXTERNAL_NET any' >> /etc/snort/snort.conf"
sudo bash -c "echo 'include \$SNORT_DIR/local.rules' >> /etc/snort/snort.conf"

echo "Creating Snort rules..."
cat <<EOL | sudo tee $SNORT_DIR/custom_rules.rules

alert tcp any any -> \$HOME_NET 21 (msg:"FTP Brute Force Attempt Detected"; flow:to_server; detection_filter:track by_src, count 5, seconds 60; reference:nessus,105616; classtype:attempted-admin; sid:1000001; rev:1;)

alert tcp any any -> \$HOME_NET 22 (msg:"SSH Brute Force Attempt Detected"; flow:to_server; detection_filter:track by_src, count 5, seconds 60; reference:nessus,101042; classtype:attempted-admin; sid:1000002; rev:1;)

alert tcp \$EXTERNAL_NET any -> \$HOME_NET any (msg:"Port Scan Detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 60; classtype:attempted-recon; sid:1000003; rev:1;)

alert tcp any any -> \$HOME_NET any (msg:"SYN Flood Detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 1; classtype:attempted-dos; sid:1000004; rev:1;)

alert http \$EXTERNAL_NET any -> \$HOME_NET any (msg:"Command Injection Attempt Detected"; content:"|3B|"; http_uri; classtype:web-application-attack; sid:1000005; rev:1;)

alert http \$EXTERNAL_NET any -> \$HOME_NET any (msg:"XSS Attempt Detected"; content:"<script>"; http_client_body; classtype:web-application-attack; sid:1000006; rev:1;)

alert udp any any -> \$HOME_NET 53 (msg:"DNS Spoofing Attempt Detected"; classtype:bad-unknown; sid:1000007; rev:1;)

alert tcp any any -> \$HOME_NET 3389 (msg:"RDP Brute Force Attempt Detected"; flow:to_server; detection_filter:track by_src, count 5, seconds 60; reference:nessus,101063; classtype:attempted-admin; sid:1000008; rev:1;)

alert tcp \$EXTERNAL_NET any -> \$HOME_NET any (msg:"SQL Injection Attempt Detected"; content:"select"; http_uri; classtype:web-application-attack; sid:1000009; rev:1;)

alert wlan wlan.fc.type_subtype == 0x0c (msg:"Wi-Fi Deauthentication Attack Detected"; classtype:bad-unknown; sid:1000010; rev:1;)

alert wlan wlan.fc.type_subtype == 0x04 (msg:"Wi-Fi Probe Request Detected"; classtype:attempted-recon; sid:1000011; rev:1;)

alert wlan wlan.fc.type_subtype == 0x00 (msg:"Wi-Fi WPS Attack Detected"; classtype:bad-unknown; sid:1000012; rev:1;)
EOL

echo "Updating the Snort configuration file..."
sudo bash -c "echo 'include \$SNORT_DIR/custom_rules.rules' >> /etc/snort/snort.conf"

echo "Configuring Snort..."
sudo systemctl restart snort

echo "Snort has been successfully installed and rules have been successfully added!"
