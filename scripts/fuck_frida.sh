#!/bin/bash

# Check if correct number of arguments provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <device_name> <start|shutdown> <frida_server_path>"
    exit 1
fi

device_name="$1"
action="$2"
frida_server_path="$3"

if [ "$action" == "start" ]; then
    # Start Frida server
    adb -s "$device_name" shell su -c "$frida_server_path" &
    echo "Frida server started on device $device_name."
elif [ "$action" == "shutdown" ]; then
    # Shutdown Frida server
    pid=$(frida-ps -D $device_name | grep frida | awk '{print $1}')
    echo $pid
    if [ -n "$pid" ]; then
        adb -s "$device_name" shell su -c "kill -9 $pid"
        echo "Frida server shutdown on device $device_name."
    else
        echo "Frida server is not running on device $device_name."
    fi
else
    echo "Invalid action. Please choose 'start' or 'shutdown'."
    exit 1
fi
