"""
Learn APP's model
"""
import os
import json
from appium import webdriver
from selenium.webdriver.common.by import By
from selenium.common import exceptions
import time
import socket
import subprocess, signal
import shutil
from log import mlog
import packet_parser
from config import device_appium_config


manually_flag = True
test_count = 1
# test_click_list = ["USU1CWRU2"]
# test_click_list = ["SAU1CWRU2"]
test_click_list = ["DCU1"]


class LearnCls:
    def __init__(self, scan_folder_name, device_name):
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
        self.APPIUM_PATH = "/home/ubuntu1604/.nvm/versions/node/v12.22.12/bin/appium"

        # get config of device
        self.DEVICE_CONFIG_DICT = device_appium_config.get_device_config_by_name(device_name)
        if not self.DEVICE_CONFIG_DICT:
            mlog.log_func(mlog.ERROR, "Do not have device_name: " + device_name + ". Please check your input.")
            print("Device_name list: ", device_appium_config.get_dev_list())
            exit(10)

        self.APK_NAME = self.DEVICE_CONFIG_DICT["appPackage"]
        self.APPIUM_IP = self.DEVICE_CONFIG_DICT["additionalMess"]["appium_ip"]
        self.APPIUM_PORT = self.DEVICE_CONFIG_DICT["additionalMess"]["port"]
        self.HOME_PAGE_ACT = self.DEVICE_CONFIG_DICT["additionalMess"]["homePage"]
        self.WIRELESS_CARD = self.DEVICE_CONFIG_DICT["additionalMess"]["wirelessCard"]

        # remove additional message
        del self.DEVICE_CONFIG_DICT["additionalMess"]

        # modify wireless card message in script
        self.modify_mitm_script()
        self.modify_frida_script()

        # start appium for listen
        mlog.log_func(mlog.LOG, "Start appium service....")
        self.start_appium_server(self.APPIUM_PATH)
        time.sleep(3)
        mlog.log_func(mlog.LOG, "SSL Pinning disabled")


        # communication information
        self.LOCAL_IP = ""
        self.LOCAL_PORT = 7009
        self.SERVER_IP = "127.0.0.1"
        self.SERVER_PORT = 9999
        self.SOCKET = ""

        # test flag and other info
        self.update_act_flag = False
        self.admin_password = "admin"
        self.cur_packet_name = ""

    def modify_mitm_script(self):
        # modify script
        lines = []
        with open(self.SCRIPTS_FOLDER + "launch_mitm.bash", "r") as f:
            for line in f.readlines():
                lines.append(line)
        lines[1] = 'WIRELESS_CARD="' + self.WIRELESS_CARD + '"\n'
        lines[2] = 'KEY_LOG_FILE="' + self.PACKET_ROOT_PATH + 'sslkeylogfile.txt"\n'
        with open(self.SCRIPTS_FOLDER + "launch_mitm.bash", "w") as f:
            for line in lines:
                f.write(line)
        lines.clear()  # clear

    def modify_frida_script(self):
        lines = []
        with open(self.SCRIPTS_FOLDER + "start_pinning_frida_script.bash", "r") as f:
            for line in f.readlines():
                lines.append(line)
        lines[1] = 'target_app="' + self.APK_NAME + '"\n'
        lines[2] = 'select_device="' + self.DEVICE_CONFIG_DICT["udid"] + '"\n'
        lines[3] = 'script_path="' + self.SCRIPTS_FOLDER + 'pinning_disable.js"'
        with open(self.SCRIPTS_FOLDER + "start_pinning_frida_script.bash", "w") as f:
            for line in lines:
                f.write(line)
        lines.clear()  # clear

    def start_tshark(self, action_name):
        # admin_proc
        admin_proc = subprocess.Popen(["echo", self.admin_password], stdout=subprocess.PIPE)

        # start tshark
        if not os.path.exists(self.PACKET_ROOT_PATH):
            os.mkdir(self.PACKET_ROOT_PATH)
        self.cur_packet_name = action_name + '_' + str(int(time.time())) + ".pcapng"
        mlog.log_func(mlog.LOG, "Start capturing, save in file: " + self.cur_packet_name)
        cur_packet_path = self.PACKET_ROOT_PATH + self.cur_packet_name
        with open(self.LOG_FOLDER_PATH + "tshark_log_file.txt", "w") as log_file:
            a = subprocess.Popen(["sudo", "-S", "tshark", "-i", self.WIRELESS_CARD, "-w", cur_packet_path],
                                 stdin=admin_proc.stdout, stdout=log_file)

        # kill mitm
        self.kill_mitm()

        # start mitm
        command = "sudo -S bash " + self.SCRIPTS_FOLDER + "launch_mitm.bash"
        mitm_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout, stdout=subprocess.PIPE)

        admin_proc.kill()

    def stop_tshark(self, with_error=0):
        admin_proc = subprocess.Popen(["echo", self.admin_password], stdout=subprocess.PIPE)

        cur_packet_path = self.PACKET_ROOT_PATH + self.cur_packet_name
        # stop tshark and chmod
        self.kill_tshark()
        stop_proc = subprocess.Popen(["sudo", "-S", "chmod", "777", cur_packet_path],
                                     stdin=admin_proc.stdout)

        # # stop ssl pinning
        # self.kill_frida()

        # kill mitm
        self.kill_mitm()

        # chmod sslkeyfile
        subprocess.check_call(["sudo", "-S", "chmod", "777", self.PACKET_ROOT_PATH + 'sslkeylogfile.txt'],
                              stdin=admin_proc.stdout)
        # rename sslkeyfile
        os.rename(self.PACKET_ROOT_PATH + 'sslkeylogfile.txt', cur_packet_path.split(".")[0] + ".txt")

        cur_packet_folder = cur_packet_path.split(".")[0][:-11] + '/'
        # move file to it's folder
        if not os.path.exists(cur_packet_folder):
            os.makedirs(cur_packet_folder)
        shutil.move(cur_packet_path.split(".")[0] + ".txt", cur_packet_folder)
        shutil.move(cur_packet_path, cur_packet_folder)

        admin_proc.kill()

    def kill_mitm(self):
        admin_proc = subprocess.Popen(["echo", self.admin_password], stdout=subprocess.PIPE)
        # get process id
        file_name = self.SCRIPTS_FOLDER + "1.txt"
        command = "sudo -S netstat -tunlp|grep 8080 > " + file_name
        # save_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout, stdout=subprocess.PIPE)
        os.system('echo %s | sudo -S %s' % (self.admin_password, command))

        # parse id and kill mitm process
        if os.path.exists(file_name):
            with open(file_name, "r") as f:
                lines = f.readlines()
                if lines:
                    process_id = lines[0].split()[-1].split("/")[0]
                    command = "sudo -S kill -9 " + process_id
                    # temp_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout)
                    os.system('echo %s | sudo -S %s' % (self.admin_password, command))
            os.remove(file_name)

        # clear iptables
        command = "sudo -S bash " + self.SCRIPTS_FOLDER + "clear_iptables.bash"
        os.system('echo %s | sudo -S %s' % (self.admin_password, command))

        admin_proc.kill()

    def kill_tshark(self):
        fine_name = self.SCRIPTS_FOLDER + "temp_tshark_ps"
        command = "ps -aux|grep tshark > " + fine_name
        os.system(command)
        with open(fine_name, "r") as f:
            lines = f.readlines()
        if len(lines) > 1:
            admin_proc = subprocess.Popen(["echo", self.admin_password], stdout=subprocess.PIPE)
            for lin in lines[:-2]:
                porc_id = lin.split()[1]
                command = "sudo -S kill -9 " + porc_id
                temp_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout)
            admin_proc.kill()
        os.remove(fine_name)

    def start_frida_hook(self):
        # start disable ssl pinning
        command = "bash " + self.SCRIPTS_FOLDER + "pinning_disable.js"
        sslpin_process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)

    def stop_frida_hook(self):
        fine_name = self.SCRIPTS_FOLDER + "temp_tshark_ps"
        command = "ps -aux|grep frida > " + fine_name
        os.system(command)
        with open(fine_name, "r") as f:
            lines = f.readlines()
        if len(lines) > 1:
            admin_proc = subprocess.Popen(["echo", self.admin_password], stdout=subprocess.PIPE)
            for lin in lines[:-1]:
                porc_id = lin.split()[1]
                command = "sudo -S kill -9 " + porc_id
                temp = subprocess.Popen(command.split(), stdin=admin_proc.stdout)
            admin_proc.kill()
        os.remove(fine_name)

    def start_appium_server(self, path_to_appium):
        path = "/".join(path_to_appium.split("/")[:-1]) + ":"
        os.environ['PATH'] = path + os.environ['PATH']
        command = f"{path_to_appium} -a 127.0.0.1 -p {self.APPIUM_PORT} --session-override"
        with open(self.LOG_FOLDER_PATH + "appium_log.txt", "w") as log_file:
            process = subprocess.Popen(command, stdout=log_file, stderr=subprocess.STDOUT, shell=True, preexec_fn=os.setsid)
        self.appium_process = process

    def stop_appium_server(self):
        try:
            self.appium_process.terminate()
            time.sleep(1)
            os.killpg(os.getpgid(self.appium_process.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass

    def get_tg_dict(self) -> dict:
        result = {}

        with open(self.ACT_TG_FILE, "r") as f:
            result.update(json.load(f))
        with open(self.ADD_TG_FILE, "r") as f:
            result.update(json.load(f))

        return result

    def create_socket(self):
        mlog.log_func(mlog.LOG, "Start connecting to server...")
        self.SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SOCKET.bind((self.LOCAL_IP, self.LOCAL_PORT))
        self.SOCKET.connect((self.SERVER_IP, self.SERVER_PORT))
        mlog.log_func(mlog.LOG, "Connection build")

    def get_input_from_learner(self):
        if manually_flag:
            return test_click_list
        else:
            # communicate with the server
            message = self.SOCKET.recv(1024)
            message_type = message[0]
            context = message[1:].decode('utf-8')
            if message_type == 1:
                print("[LOG] Receive input: " + context)
                '''
                '''
                # Add the response to Reset, which needs to be deleted later
                if context == "Reset":
                    self.SOCKET.sendall(bytes([message_type]) + "Reset has received".encode('utf-8'))
                '''
                '''
            else:
                print("[ERROR] Don't receive input message")
            return context

    def parse_packet_and_get_response(self, packet_name) -> str:
        return packet_parser.get_new_op_class_for_response(packet_name)

    def response_to_learner(self, output):
        """
        Tell the learner the output of operation.
        :param output: result str from packet parsing
        """
        reply_message = bytes([1]) + output.encode('utf-8')
        self.SOCKET.sendall(reply_message)

    def dfs_search(self, act1, act2):
        """
        使用dfs算法看是否在Activity中存在从act1切换到act2的路径
        """

        def search_graph(graph, start, end):
            results = []
            generate_path(graph, [start], end, results)
            results.sort(key=lambda x: len(x))
            return results

        def generate_path(graph, path, end, results):
            state = path[-1]
            if state == end:
                results.append(path)
            else:
                for arc in graph[state]:
                    if arc not in path:
                        generate_path(graph, path + [arc], end, results)

        act_tg_dict = self.get_tg_dict()

        if act1 in act_tg_dict.keys():
            for nodes in act_tg_dict.keys():
                act_tg_dict[nodes] = list(act_tg_dict[nodes].keys())

            r = search_graph(act_tg_dict, act1, act2)

            if not r:
                return None
            else:
                return r
        else:
            return None

    def start_driver(self):
        """
        read config of device and start appium driver
        :return: device driver for auto click
        """
        mlog.log_func(mlog.LOG, "Get device config:")
        mlog.log_dict_func(mlog.LOG, self.DEVICE_CONFIG_DICT)

        driver = webdriver.Remote(self.APPIUM_IP, self.DEVICE_CONFIG_DICT)

        # command = "frida -U -F " + self.APK_NAME + " -l " + self.SCRIPTS_FOLDER + "pinning_disable.js > temp_sslpinning.txt"
        # # sslpin = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        # os.system('echo %s | sudo -S %s' % (self.admin_password, command))

        self.driver = driver

    def stop_driver(self):
        self.driver.quit()
        self.stop_appium_server()

    def get_valuable_button(self, button_conf_file):
        with open(button_conf_file, "r") as f:
            valuable_button_click_path = json.load(f)

        return valuable_button_click_path

    def back_to_home(self, cur_act):
        # find path
        tg_list = self.dfs_search(cur_act, self.HOME_PAGE_ACT)

        # if tg path is existing
        if tg_list:
            act_tg_dict = self.get_tg_dict()

            tg_list = tg_list[0][1:]
            for next_act in tg_list:
                xpath = act_tg_dict[cur_act][next_act]
                self.driver.find_element(By.XPATH, xpath).click()
                cur_act = next_act
                time.sleep(0.2)
        else:
            print("[ERROR] Can not find path from [" + cur_act + "] to [" + self.HOME_PAGE_ACT + "]")
            exit(-1)

    def click_button(self, ui_name, uip_dict):
        """
        Click the button
        :param ui_name: action name will be clicked
        :param uip_dict: click path dictionary of button
        """
        if ui_name not in uip_dict.keys():
            mlog.log_func(mlog.ERROR, "UI which will be clicked is not in config/valuable_button.json")
            exit(-1)

        # get click path
        click_path_dict = uip_dict[ui_name]

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
                act_before = click_path_dict[index]["act_before"]
                act_after = click_path_dict[index]["act_after"]

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
                        mlog.log_func(mlog.ERROR, "can not find component when --- " + click_path_dict[index]["description"])
                        self.stop_tshark()
                        exit(-1)

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
                        mlog.log_func(mlog.ERROR, "can not find component when --- " + click_path_dict[index]["description"])
                        self.stop_tshark()
                        exit(-1)
            elif "posi_x" in click_path_dict[index].keys() and "posi_y" in click_path_dict[index].keys():
                self.driver.tap([(click_path_dict[index]["posi_x"], click_path_dict[index]["posi_y"])])

            # get current activity and check
            time.sleep(0.5)  # wait for activity
            cur_activity = self.driver.current_activity

    def load_alphabet(self, ui_list):
        """
        Send a reply to learner to tell the scan results.
        :param ui_list: valuable UI list
        :param server_socket: server socket to send message
        :return: response from Learner
        """
        # print log
        mlog.log_func(mlog.LOG, "send input_bat to learner...")
        print("input_bat---", ui_list)

        # communicate with the server
        message = self.SOCKET.recv(1024)
        message_type = message[0]
        context = message[1:].decode('utf-8')
        if message_type == 0 and context == "alphabet":
            mlog.log_func(mlog.LOG, "Receive alphabet send request")

            # Send reply message
            reply_context = "Succeed!"
            reply_message = bytes([message_type]) + reply_context.encode('utf-8')
            self.SOCKET.sendall(reply_message)
            mlog.log_func(mlog.LOG, "Send reply message")
        else:
            mlog.log_func(mlog.ERROR, "Don't receive alphabet send request")

        # create file for alphabet
        alphabet_file = self.LEARNLIB_FOLDER + "src/main/resources/input_bat"
        with open(alphabet_file, "w") as f:
            for item in ui_list:
                if item != ui_list[-1]:
                    f.write(item + "\n")
                else:
                    f.write(item)
        mlog.log_func(mlog.LOG, "Create the alphabet file input_bat")

        self.get_input_from_learner()
        self.response_to_learner(self.get_input_from_learner() + "_suc")


def learn_main(scan_result_name):
    # create an entity of learn
    nexus_learn_entity = LearnCls(scan_result_name, "nexus")
    # get val_buttons
    val_but_dict = nexus_learn_entity.get_valuable_button(nexus_learn_entity.VALUABLE_BUTTON_FILE)

    if not manually_flag:
        # create tcp socket and connect to server
        nexus_learn_entity.create_socket()

        # send alphabet to learner
        nexus_learn_entity.load_alphabet(list(val_but_dict.keys()))

    # start app and get driver
    nexus_learn_entity.start_driver()

    while True:
        if manually_flag:
            # get manually input list
            learner_input_list = nexus_learn_entity.get_input_from_learner()
            mlog.log_func(mlog.DEBUG, "Manually test start, total count: " + str(test_count))
            # test for test_count counts
            for count in range(test_count):
                mlog.log_func(mlog.DEBUG, "Current count: " + str(count + 1))
                # for each input in list
                for learner_input in learner_input_list:
                    if learner_input in val_but_dict.keys():
                        if nexus_learn_entity.APK_NAME + nexus_learn_entity.driver.current_activity != nexus_learn_entity.HOME_PAGE_ACT:
                            nexus_learn_entity.back_to_home(nexus_learn_entity.APK_NAME + nexus_learn_entity.driver.current_activity)
                        mlog.log_func(mlog.DEBUG, "Manually click task-----" + learner_input)
                        nexus_learn_entity.start_tshark(learner_input)
                        time.sleep(2)
                        nexus_learn_entity.click_button(learner_input, val_but_dict)
                        time.sleep(5)
                        nexus_learn_entity.stop_tshark()

                        # mlog.log_func(mlog.LOG, nexus_learn_entity.parse_packet_and_get_response(nexus_learn_entity.cur_packet_name))

                        if nexus_learn_entity.update_act_flag:
                            # update conf
                            with open(nexus_learn_entity.VALUABLE_BUTTON_FILE, "w") as f:
                                json.dump(val_but_dict, f, indent=2)

                    else:
                        break

                    # sleep
                    time.sleep(1)
            mlog.log_func(mlog.DEBUG, "Manually test finish")
            break
        else:
            # start test and get input
            learner_input = nexus_learn_entity.get_input_from_learner()

            if learner_input in val_but_dict.keys():
                if nexus_learn_entity.APK_NAME + nexus_learn_entity.driver.current_activity != nexus_learn_entity.HOME_PAGE_ACT:
                    nexus_learn_entity.back_to_home(nexus_learn_entity.APK_NAME + nexus_learn_entity.driver.current_activity)
                # print("[LOG] Click task-----" + learner_input)
                mlog.log_func(mlog.DEBUG, "Click task-----" + learner_input)
                nexus_learn_entity.start_tshark(learner_input)
                time.sleep(3)
                nexus_learn_entity.click_button(learner_input, val_but_dict)
                time.sleep(3)
                nexus_learn_entity.stop_tshark()

                if nexus_learn_entity.update_act_flag:
                    # update conf
                    with open(nexus_learn_entity.VALUABLE_BUTTON_FILE, "w") as f:
                        json.dump(val_but_dict, f, indent=2)

                nexus_learn_entity.response_to_learner("click_output")
            else:
                break

    # close android driver and shutdown frida
    nexus_learn_entity.stop_driver()

    # nexus_learn_entity.kill_frida()


if __name__ == "__main__":
    mlog.clear_log()
    learn_main("20230920183445_com.huawei.smarthome")
