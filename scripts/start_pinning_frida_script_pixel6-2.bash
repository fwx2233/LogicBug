#!/bin/bash
target_app="com.huawei.smarthome"
select_device="26151FDF6005FT"
script_path="/home/ubuntu1604/Desktop/logic_bug/learn_model/../scripts/pinning_disable.js"
frida -D $select_device -F $target_app -l $script_path