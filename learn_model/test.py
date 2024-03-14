import json
import os
import socket
import random
from collections import defaultdict
from appium import webdriver
from selenium.webdriver.common.by import By
from selenium.common import exceptions
import time
import subprocess, signal
import shutil

from learn_model import format_tools, packet_parser, get_ips
from log import mlog
from config import device_appium_config, button_constrain


class DeviceCls:
    def __init__(self, scan_folder_name, device_name, which_user, frida_flag=True):
        mlog.log_func(mlog.LOG, f"Current device: <{device_name}>, regarded as user: <{which_user}>")

        # paths
        self.ROOT_PATH = os.path.dirname(__file__)
        self.LOG_FOLDER_PATH = self.ROOT_PATH + "/../log/"
        self.PACKET_ROOT_PATH = self.ROOT_PATH + "/packets/"
        self.CONF_FOLDER_PATH = self.ROOT_PATH + "/../config/"
        self.SCRIPTS_FOLDER = self.ROOT_PATH + "/../scripts/"
        self.LEARNLIB_FOLDER = self.ROOT_PATH + "/learnlib_module/"
        self.ACT_TG_FILE = self.ROOT_PATH + "/../analyse_app/temp_scan_result/act_tg_" + scan_folder_name + ".json"
        self.ADD_TG_FILE = self.ROOT_PATH + "/../analyse_app/temp_scan_result/additional_tg_" + scan_folder_name + ".json"
        self.VALUABLE_BUTTON_FILE = self.CONF_FOLDER_PATH + "valuable_button.json"
        self.APPIUM_PATH = device_appium_config.appium_path

        # get config of device
        self.DEVICE_CONFIG_DICT = device_appium_config.get_device_config_by_name(device_name)
        if not self.DEVICE_CONFIG_DICT:
            mlog.log_func(mlog.ERROR, "Do not have device_name: " + device_name + ". Please check your input.")
            print("Device_name list: ", device_appium_config.get_device_list())
            exit(10)

        self.USER = which_user

        self.APK_NAME = self.DEVICE_CONFIG_DICT["appPackage"]
        self.APPIUM_IP = self.DEVICE_CONFIG_DICT["additionalMess"]["appium_ip"]
        self.APPIUM_PORT = self.DEVICE_CONFIG_DICT["additionalMess"]["port"]
        self.HOME_PAGE_ACT = self.DEVICE_CONFIG_DICT["additionalMess"]["homePage"]
        self.WIRELESS_CARD = self.DEVICE_CONFIG_DICT["additionalMess"]["wirelessCard"]
        self.APP_ACTIVITY = self.DEVICE_CONFIG_DICT["appActivity"]
        self.UDID = self.DEVICE_CONFIG_DICT["udid"]
        self.DEVICE_NAME = device_name

        self.DEVICE_CONFIG_DICT_FOR_APPIUM = dict()
        # remove additional message
        for key in self.DEVICE_CONFIG_DICT:
            if key != "additionalMess":
                self.DEVICE_CONFIG_DICT_FOR_APPIUM[key] = self.DEVICE_CONFIG_DICT[key]

        # get valuable_buttion_dict
        self.val_but_dict = self.get_valuable_button(self.VALUABLE_BUTTON_FILE, self.USER)

        # modify wireless card message in script
        self.modify_mitm_script()


        # start appium for listen
        self.start_appium_server(self.APPIUM_PATH)
        time.sleep(2)

        if frida_flag:
            self.modify_frida_script()
            self.start_frida_hook()
            time.sleep(10)

        # test flag and other info
        self.update_act_flag = False
        self.admin_password = "admin"
        self.cur_packet_name = ""
        self.cur_packet_folder = ""
        self.cur_packet_path = ""

    def get_valuable_button(self, button_conf_file, user) -> dict:
        with open(button_conf_file, "r") as f:
            valuable_button_click_path = json.load(f)

        if user not in valuable_button_click_path:
            mlog.log_func(mlog.ERROR, f"{user} is not in valuable_buttion.json")
            exit(-2)

        return valuable_button_click_path[user]

    def modify_mitm_script(self):
        mlog.log_func(mlog.LOG, "Modify mitm script")
        self.cur_key_log_file_path = self.PACKET_ROOT_PATH + 'sslkeylogfile.txt'

        # modify script
        lines = []
        with open(self.SCRIPTS_FOLDER + "launch_mitm.bash", "r") as f:
            for line in f.readlines():
                lines.append(line)
        # lines[1] = 'WIRELESS_CARD="' + self.WIRELESS_CARD + '"\n'
        lines[2] = 'KEY_LOG_FILE="' + self.PACKET_ROOT_PATH + 'sslkeylogfile.txt"\n'
        with open(self.SCRIPTS_FOLDER + "launch_mitm.bash", "w") as f:
            for line in lines:
                f.write(line)
        lines.clear()  # clear

        lines = []
        with open(self.SCRIPTS_FOLDER + "change_iptables.bash", "r") as f:
            for line in f.readlines():
                lines.append(line)
        lines[1] = 'WIRELESS_CARD="' + self.WIRELESS_CARD + '"\n'
        with open(self.SCRIPTS_FOLDER + "change_iptables.bash", "w") as f:
            for line in lines:
                f.write(line)

    def modify_frida_script(self):
        lines = []
        lines.append("#!/bin/bash")
        lines.append('target_app="' + self.APK_NAME + '"\n')
        lines.append('select_device="' + self.UDID + '"\n')
        lines.append('script_path="' + self.SCRIPTS_FOLDER + 'pinning_disable.js"\n')
        lines.append("frida -D $select_device -F $target_app -l $script_path")

        with open(self.SCRIPTS_FOLDER + "start_pinning_frida_script.bash", "w") as f:
            for line in lines:
                f.write(line)
        lines.clear()  # clear

    def start_tshark(self, pcapng_name):
        # admin_proc
        admin_proc = subprocess.Popen(["echo", self.admin_password], stdout=subprocess.PIPE)

        self.cur_packet_name = pcapng_name + '_' + str(int(time.time())) + ".pcapng"

        # create folder
        self.cur_packet_folder = self.PACKET_ROOT_PATH + self.cur_packet_name[:-7] + "/"
        if not os.path.exists(self.cur_packet_folder):
            os.makedirs(self.cur_packet_folder)

        self.cur_packet_path = self.cur_packet_folder + self.cur_packet_name

        # kill mitm
        self.kill_mitm()
        self.clear_iptables()

        mlog.log_func(mlog.LOG, "Start capturing, save in file: " + self.PACKET_ROOT_PATH + self.cur_packet_name)
        with open(self.LOG_FOLDER_PATH + "tshark_log_file.txt", "w") as log_file:
            pass
        a = subprocess.Popen(["tshark", "-i", self.WIRELESS_CARD, "-w", self.cur_packet_path], stdout=open(self.LOG_FOLDER_PATH + "tshark_log_file.txt"))

        self.change_iptables()
        self.start_mitm()

        admin_proc.kill()

    def stop_tshark(self, with_error=0):
        admin_proc = subprocess.Popen(["echo", self.admin_password], stdout=subprocess.PIPE)
        # stop tshark and chmod
        self.kill_tshark()

        # rename sslkeyfile
        os.rename(self.PACKET_ROOT_PATH + 'sslkeylogfile.txt',
                  self.PACKET_ROOT_PATH + self.cur_packet_name.split(".")[0] + ".txt")

        # move file to it's corresponding folder
        shutil.move(self.PACKET_ROOT_PATH + self.cur_packet_name.split(".")[0] + ".txt", self.cur_packet_folder)

        # remove file
        os.remove(self.LOG_FOLDER_PATH + "tshark_log_file.txt")

        admin_proc.kill()

    def start_mitm(self):
        # start mitm
        mlog.log_func(mlog.LOG, "launch mitm")
        with open(self.LOG_FOLDER_PATH + "mitm_log.txt", "w") as log:
            mitm_proc = subprocess.Popen(["bash", self.SCRIPTS_FOLDER+"launch_mitm.bash"], stdout=log)
        # mitm_proc = subprocess.Popen(["bash", self.SCRIPTS_FOLDER+"launch_mitm.bash"], stdout=open(self.LOG_FOLDER_PATH + "mitm_log.txt"))

    def kill_mitm(self):
        mlog.log_func(mlog.LOG, "kill mitm and clear iptable rules")

        # get process id
        file_name = self.ROOT_PATH + "/1.txt"
        command = "ps aux|grep mitmdump > " + file_name
        os.system(command)

        # parse id and kill mitm process
        if os.path.exists(file_name):
            with open(file_name, "r") as f:
                lines = f.readlines()
                if lines:
                    process_id = lines[0].split()[1]
                    command = "kill -9 " + process_id
                    os.system('echo %s | sudo -S %s' % (self.admin_password, command))
            os.remove(file_name)

        # remove log
        if os.path.exists(self.LOG_FOLDER_PATH + "mitm_log.txt"):
            os.remove(self.LOG_FOLDER_PATH + "mitm_log.txt")

    def change_iptables(self):
        # change iptable rules
        mlog.log_func(mlog.LOG, "Change iptable rules")
        command = "bash " + self.SCRIPTS_FOLDER + "change_iptables.bash"
        os.system('echo %s | sudo -S %s' % (self.admin_password, command))

    def clear_iptables(self):
        mlog.log_func(mlog.LOG, "Clear iptable rules")
        # clear iptables
        command = "bash " + self.SCRIPTS_FOLDER + "/clear_iptables.bash"
        os.system('echo %s | sudo -S %s' % (self.admin_password, command))

    def kill_tshark(self):
        mlog.log_func(mlog.LOG, "kill tshark")

        fine_name = self.SCRIPTS_FOLDER + "temp_tshark_ps"
        command = "ps -aux|grep tshark > " + fine_name
        os.system(command)

        with open(fine_name, "r") as f:
            lines = f.readlines()
        if len(lines) > 1:
            # admin_proc = subprocess.Popen(["echo", self.admin_password], stdout=subprocess.PIPE)
            for lin in lines[:-2]:
                porc_id = lin.split()[1]
                command = "sudo -S kill -9 " + porc_id
                # temp_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout)
                os.system('echo %s | sudo -S %s' % (self.admin_password, command))
            # admin_proc.kill()
        os.remove(fine_name)

    def start_frida_hook(self):
        mlog.log_func(mlog.LOG, "Start frida to ban the SSL Pinning")
        # start disable ssl pinning
        command = "bash " + self.SCRIPTS_FOLDER + "start_pinning_frida_script.bash"
        sslpin_process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stdin=open("/dev/null"))

    def stop_frida_hook(self):
        fine_name = self.SCRIPTS_FOLDER + "temp_tshark_ps"
        command = "ps -aux|grep frida > " + fine_name
        os.system(command)
        with open(fine_name, "r") as f:
            lines = f.readlines()
        if len(lines) > 1:
            # admin_proc = subprocess.Popen(["echo", self.admin_password], stdout=subprocess.PIPE)
            for lin in lines[:-1]:
                porc_id = lin.split()[1]
                command = "sudo -S kill -9 " + porc_id
                # temp = subprocess.Popen(command.split(), stdin=admin_proc.stdout)
                os.system('echo %s | sudo -S %s' % (self.admin_password, command))
            # admin_proc.kill()
        os.remove(fine_name)

    def start_appium_server(self, path_to_appium):
        mlog.log_func(mlog.LOG, "Start appium service....")

        path = "/".join(path_to_appium.split("/")[:-1]) + ":"
        os.environ['PATH'] = path + os.environ['PATH']
        command = f"{path_to_appium} -a 127.0.0.1 -p {self.APPIUM_PORT} --session-override"
        with open(self.LOG_FOLDER_PATH + self.UDID + "_appium_log.txt", "w") as log_file:
            process = subprocess.Popen(command, stdout=log_file, stderr=subprocess.STDOUT, shell=True,
                                       preexec_fn=os.setsid)
        self.appium_process = process

    def stop_appium_server(self):
        try:
            self.appium_process.terminate()
            time.sleep(1)
            os.killpg(os.getpgid(self.appium_process.pid), signal.SIGTERM)
            if os.path.exists(self.LOG_FOLDER_PATH + self.UDID + "_appium_log.txt"):
                os.remove(self.LOG_FOLDER_PATH + self.UDID + "_appium_log.txt")
        except ProcessLookupError:
            mlog.log_func(mlog.ERROR, "ProcessLookupError from kill appium server")
            pass

    def parse_packet_and_get_response(self, database, packet_name, op_name, start_time, end_time) -> str:
        return packet_parser.get_new_op_class_for_response(database, packet_name, self.cur_key_log_file_path, op_name,
                                                           start_time, end_time)

    def start_driver(self):
        """
        read config of device and start appium driver
        :return: device driver for auto click
        """
        mlog.log_func(mlog.LOG, "Get device config:")
        mlog.log_dict_func(mlog.LOG, self.DEVICE_CONFIG_DICT_FOR_APPIUM)

        driver = webdriver.Remote(self.APPIUM_IP, self.DEVICE_CONFIG_DICT_FOR_APPIUM)

        self.driver = driver

    def start_driver_and_init(self):
        self.start_driver()
        while not self.back_to_home():
            # self.stop_and_restart_app()
            pass

    def stop_driver(self):
        mlog.log_func(mlog.LOG, f"Driver <{self.DEVICE_NAME}> quit")
        self.driver.quit()
        self.stop_appium_server()

    def stop_learn(self):
        mlog.log_func(mlog.LOG, "Stop Learning...")
        # stop packet capture, close android driver
        self.stop_tshark()
        # kill mitm
        self.kill_mitm()
        self.clear_iptables()
        # stop hook
        self.stop_frida_hook()

    def stop_and_restart_app(self):
        mlog.log_func(mlog.LOG, f"Device <{self.DEVICE_NAME}> stop and restart APP <{self.APK_NAME}>")
        command = f"adb -s {self.UDID} shell am force-stop {self.APK_NAME} && adb -s {self.UDID} shell am start -n {self.APK_NAME}/{self.APP_ACTIVITY}"
        os.system(command)

    def back_to_home(self):
        mlog.log_func(mlog.LOG, "Back to homepage")
        command = f"adb -s {self.UDID} shell am start -n {self.APK_NAME}/{self.APP_ACTIVITY}"
        back_count = 0
        while self.APK_NAME + self.driver.current_activity != self.HOME_PAGE_ACT:
            os.system(command)
            time.sleep(0.5)
            back_count += 1

            # something wrong with frida or appium or app
            if back_count > 10:
                mlog.log_func(mlog.ERROR, "Something wrong with frida or appium or app, please [restart app and restart learn]")

                # restart app
                self.stop_and_restart_app()

                from scripts import do_kill
                do_kill.kill_main()

                return False

        # back to home page
        while not self.click_button("BackHome"):
            mlog.log_func(mlog.LOG, "Press back-system")
            self.driver.back()
            time.sleep(0.5)

        return True

    def click_and_save(self, ui_name, waiting_time=3):
        """
        Click the button
        :param ui_name: action name
        :param waiting_time:
        :return:
        """
        mlog.log_func(mlog.LOG, f"<{self.USER}> Click task-----{ui_name}")
        start_time = time.time()
        if self.click_button(ui_name):
            time.sleep(waiting_time)
            end_time = time.time()
            # save log
            action_log_file = self.PACKET_ROOT_PATH + self.cur_packet_name.split(".")[
                0] + "/" + ui_name + "/" + ui_name + '_' + str(int(start_time)) + ".txt"
            if not os.path.exists(self.PACKET_ROOT_PATH + self.cur_packet_name.split(".")[0] + "/" + ui_name + "/"):
                os.makedirs(self.PACKET_ROOT_PATH + self.cur_packet_name.split(".")[0] + "/" + ui_name + "/")
            with open(action_log_file, "w") as log:
                log.write(self.cur_packet_name)
                log.write('\n')
                log.write(str(start_time))
                log.write('\n')
                log.write(str(end_time))
            get_ips.get_and_save_ip_list_by_apk(self.APK_NAME, self.UDID)
            return [start_time, end_time]
        return False

    def click_button(self, ui_name):
        """
        Click the button
        :param ui_name: action name will be clicked
        """
        is_special_op = False
        if ui_name in self.val_but_dict["Special"]:
            is_special_op = True
        elif ui_name not in self.val_but_dict.keys():
            mlog.log_func(mlog.ERROR, f"UI <{ui_name}> which will be clicked is not in config/valuable_button.json")
            return False

        # get click path
        if not is_special_op:
            click_path_dict = self.val_but_dict[ui_name]
        else:
            click_path_dict = self.val_but_dict["Special"][ui_name]

        # click one by one
        for index in click_path_dict.keys():
            # waiting
            if "waiting_time" in click_path_dict[index].keys():
                time.sleep(click_path_dict[index]["waiting_time"])

            if "description" in click_path_dict[index].keys():
                mlog.log_func(mlog.LOG, index + "---" + click_path_dict[index]["description"], t_count=1)
            else:
                mlog.log_func(mlog.LOG, index + "---" + ui_name + ": " + click_path_dict[index], t_count=1)

            # get location and click
            if "xpath" in click_path_dict[index].keys():
                cur_ui_xpath = click_path_dict[index]["xpath"]

                # if exist
                try:
                    # click
                    target = self.driver.find_element(By.XPATH, cur_ui_xpath)
                    if self.update_act_flag:
                        click_path_dict[index]["act_before"] = self.driver.current_activity
                    target.click()
                    if self.update_act_flag:
                        click_path_dict[index]["act_after"] = self.driver.current_activity
                except exceptions.NoSuchElementException:
                    # retry for 3 times
                    if_find_flag = False
                    for temp_index in range(3):
                        time.sleep(2)
                        try:
                            self.driver.find_element(By.XPATH, cur_ui_xpath).click()
                            if_find_flag = True
                            break
                        except exceptions.NoSuchElementException:
                            pass
                    if not if_find_flag:
                        mlog.log_func(mlog.LOG,
                                      "can not find component when --- " + click_path_dict[index]["description"])
                        return False

            # find element by resource id
            elif "resource_id" in click_path_dict[index].keys():
                cur_ui_id = click_path_dict[index]["resource_id"]
                id_index = click_path_dict[index]["rec_index"]
                act_before = click_path_dict[index]["act_before"]
                act_after = click_path_dict[index]["act_after"]

                # click with resource_id
                try:
                    target = self.driver.find_element(By.ID, cur_ui_id)
                    if self.update_act_flag:
                        click_path_dict[index]["act_before"] = self.driver.current_activity
                    target.click()
                    if self.update_act_flag:
                        click_path_dict[index]["act_after"] = self.driver.current_activity
                except exceptions.NoSuchElementException:
                    # retry for 3 times
                    if_find_flag = False
                    for temp_index in range(3):
                        time.sleep(2)
                        try:
                            self.driver.find_element(By.ID, cur_ui_id).click()
                            if_find_flag = True
                            break
                        except exceptions.NoSuchElementException:
                            pass
                    if not if_find_flag:
                        mlog.log_func(mlog.LOG,
                                      "can not find component when --- " + click_path_dict[index]["description"])
                        return False
            elif "posi_x" in click_path_dict[index].keys() and "posi_y" in click_path_dict[index].keys():
                self.driver.tap([(click_path_dict[index]["posi_x"], click_path_dict[index]["posi_y"])])

            # get current activity and check
            time.sleep(0.5)  # wait for activity
            cur_activity = self.driver.current_activity

        return True


print("Start connecting to server...")

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

socket.bind(("", 7009))

socket.connect(("127.0.0.1", 9999))

print("Connection build")

with open(os.path.dirname(__file__) + "/../config/" + "valuable_button.json", "r") as val_but_file:
    but_dict = json.load(val_but_file)

overlook_list = ["user1|AS", "user1|SDU1CWR", "user1|VD1S", #"user1|ADU1CWR", "user1|RDU1CWR", "user1|DCU1",
                     "user2|AcceptDeviceShare", "user2|RejectDeviceShare", "user2|AcceptInvite", "user2|DenyInvite"]

ui_list = []
for user, button_dict in but_dict.items():
    button_name_list = list(button_dict.keys())
    for item in button_name_list:
        if item != "Special" and (user + "|" + item) not in overlook_list:
            ui_list.append(user + "|" + item)

message = socket.recv(1024)
message_type = message[0]
context = message[1:].decode('utf-8')
if message_type == 0 and context == "alphabet":
    print("Receive alphabet send request")

    # create file for alphabet
    alphabet_file = os.path.dirname(__file__) + "/learnlib_module/src/main/resources/input_bat"
    with open(alphabet_file, "w") as f:
        for item in ui_list:
            if item != ui_list[-1]:
                f.write(item + "\n")
            else:
                f.write(item)
    print("Create the alphabet file input_bat")

    # Send reply message
    reply_context = "Succeed!"
    reply_message = bytes([0]) + reply_context.encode('utf-8')
    socket.sendall(reply_message)
    print("Send alphabet success")
else:
    print("Don't receive alphabet send request")

reset_count = 0

pro_end_flag = False

while not pro_end_flag:
    # create device entity for click
    pixel7_entity = DeviceCls("20230920183445_com.huawei.smarthome", "pixel7", "user1", frida_flag=True)
    pixel7_entity.start_driver_and_init()

    while True:
        message = socket.recv(1024)
        message_type = message[0]
        context = message[1:].decode('utf-8')
        if message_type == 0:
            print("Receive system message: " + context)
        elif message_type == 1:
            print("Receive learnlib message: " + context)
        elif message_type == 2:
            print("Receive query message: " + context)
        else:
            print("Don't receive input message")

        option = context

        if option == "closeConnect":
            print("Stop learning...")
            reply_message = bytes([1]) + "close the client".encode('utf-8')
            print("Send reply message: " + "close the client")
            socket.sendall(reply_message)
            print("Close the socket...")
            socket.close()
            break

        if option == "checkCounterExample":
            print("Check the counter example...")
            reply_message = bytes([1]) + "WaitForChecking".encode('utf-8')
            print("Send reply message: " + "WaitForChecking")
            socket.sendall(reply_message)
            continue

        if option == "Reset":
            reset_count += 1
            if reset_count > 2:
                pro_end_flag = True
                break
            print("Reset")
            reply_message = bytes([1]) + "Reset_suc".encode('utf-8')
            print("Send reply message: " + "Reset_suc")
            socket.sendall(reply_message)
            continue

        user = option.split("|")[0]
        option = option.split("|")[-1]

        reply = input()
        print(reply)
        if reply.lower() == "qwe":
            pixel7_entity.stop_and_restart_app()
            reply = "RestartLearning"
            reply_message = bytes([1]) + reply.encode('utf-8')
            print("Send reply message: " + reply)
            socket.sendall(reply_message)
            pixel7_entity.stop_driver()
            pixel7_entity.stop_appium_server()
            break

        reply_message = bytes([1]) + reply.encode('utf-8')
        print("Send reply message: " + reply)
        socket.sendall(reply_message)

    print("OK")

print("close")
socket.close()
