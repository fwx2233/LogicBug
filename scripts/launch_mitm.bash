#!/bin/bash
WIRELESS_CARD="wlxc01c30151c62"
KEY_LOG_FILE="/home/ubuntu1604/Desktop/logic_bug/learn_model/packets/sslkeylogfile.txt"
#echo Wireless:"$WIRELESS_CARD"
#echo Log_file:$KEY_LOG_FILE

# delete current key log file and create a new one
rm $KEY_LOG_FILE
touch $KEY_LOG_FILE

sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.all.send_redirects=0

# set iptables rules
# flush rules of wireless card
sudo iptables -F PREROUTING -t nat

# set redirect port(MQTT: 8883, HTTP: 80, HTTS: 443)
sudo iptables -t nat -A PREROUTING -i $WIRELESS_CARD -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i $WIRELESS_CARD -p tcp --dport 443 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i $WIRELESS_CARD -p tcp --dport 8883 -j REDIRECT --to-port 8080

# launch mitmproxy on transparent mode
SSLKEYLOGFILE="$KEY_LOG_FILE" mitmdump --mode transparent -v --ssl-insecure --tcp-host '.*' -p 8080
