# set iptables rules
# flush rules of wireless card
sudo iptables -F PREROUTING -t nat
