#!/bin/bash
target_app="com.huawei.smarthome"
select_device="5VT7N15A29000275"
script_path="/home/ubuntu1604/Desktop/logic_bug/learn_model/../scripts/pinning_disable.js"
frida -D $select_device -F $target_app -l $script_path