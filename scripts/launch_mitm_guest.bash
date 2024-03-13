#!/bin/bash
KEY_LOG_FILE="/home/ubuntu1604/Desktop/logic_bug/learn_model/packets/sslkeylogfile_guest.txt"

# delete current key log file and create a new one
rm $KEY_LOG_FILE
touch $KEY_LOG_FILE

# launch mitmproxy on transparent mode
SSLKEYLOGFILE="$KEY_LOG_FILE" /usr/local/python/python3.8/bin/mitmdump --mode transparent -v --ssl-insecure --tcp-host '.*' -p 8081
