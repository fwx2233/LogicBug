#!/bin/bash
target_app="com.huawei.smarthome"
select_device="1C071FDF60020H"
script_path="/home/ubuntu1604/Desktop/logic_bug/learn_model/../scripts/pinning_disable.js"
frida -D $select_device -F $target_app -l $script_path