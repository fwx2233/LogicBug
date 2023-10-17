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
import subprocess


class LearnCls:
    def __init__(self):
        # paths
        self.ROOT_PATH = os.path.dirname(__file__)
        self.PACKET_ROOT_PATH = self.ROOT_PATH + "/packets/"
        self.CONF_FOLDER_PATH = self.ROOT_PATH + "/../config/"
        self.SCRIPTS_FOLDER = self.ROOT_PATH + "/../scripts/"
        self.ACT_TG_FILE = self.ROOT_PATH + "/../analyse_app/temp_scan_result/act_tg.json"
        self.ADD_TG_FILE = self.ROOT_PATH + "/../analyse_app/temp_scan_result/additional_tg.json"
        self.PHONE_CONF_FILE = self.CONF_FOLDER_PATH + "device.json"
        self.VALUABLE_BUTTON_FILE = self.CONF_FOLDER_PATH + "valuable_button.json"

        # get config of device
        if not os.path.exists(self.PHONE_CONF_FILE):
            print("[ERROR] Setting device wrong, no such file: " + self.PHONE_CONF_FILE)
            exit(-1)
        with open(self.PHONE_CONF_FILE) as f:
            device = json.load(f)
            self.APK_NAME = device["appPackage"]

        # device info
        self.APPIUM_IP = "http://127.0.0.1:4723/wd/hub"
        self.bool_conf_name = ["noReset", "dontStopAppOnReset"]
        self.HOME_PAGE_ACT = "com.huawei.smarthome.activity.MainActivity"
        self.WIRELESS_CARD = "wlxc01c30151c62"

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

        # communication information
        self.LOCAL_IP = ""
        self.LOCAL_PORT = 7009
        self.SERVER_IP = "192.168.50.206"
        self.SERVER_PORT = 7009

        # test flag and other info
        self.update_act_flag = False
        self.admin_password = "admin"
        self.cur_packet_name = ""

    def start_tshark(self, action_name):
        # admin_proc
        admin_proc = subprocess.Popen(["echo", self.admin_password], stdout=subprocess.PIPE)

        # start tshark
        if not os.path.exists(self.PACKET_ROOT_PATH):
            os.mkdir(self.PACKET_ROOT_PATH)
        self.cur_packet_name = self.PACKET_ROOT_PATH + action_name + '_' + str(int(time.time())) + ".pcapng"
        a = subprocess.Popen(["sudo", "-S", "tshark", "-i", self.WIRELESS_CARD, "-w", self.cur_packet_name], stdin=admin_proc.stdout)

        # kill mitm
        self.kill_mitm()

        # start mitm
        command = "sudo -S bash " + self.SCRIPTS_FOLDER + "launch_mitm.bash"
        mitm_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout, stdout=subprocess.PIPE)

        # # start disable ssl pinning
        # command = "frida -U -F " + self.APK_NAME + " -l " + self.SCRIPTS_FOLDER + "pinning_disable.js"
        # sslpin = subprocess.Popen(command.split(), stdout=subprocess.PIPE)

        admin_proc.kill()

    def stop_tshark(self, with_error=0):
        admin_proc = subprocess.Popen(["echo", self.admin_password], stdout=subprocess.PIPE)

        # stop tshark and chmod
        self.kill_tshark()
        stop_proc = subprocess.Popen(["sudo", "-S", "chmod", "777", self.cur_packet_name],
                                     stdin=admin_proc.stdout)

        # # stop ssl pinning
        # self.kill_frida()

        # kill mitm
        self.kill_mitm()

        # chmod sslkeyfile
        subprocess.check_call(["sudo", "-S", "chmod", "777", self.PACKET_ROOT_PATH + 'sslkeylogfile.txt'],
                              stdin=admin_proc.stdout)
        # rename sslkeyfile
        os.rename(self.PACKET_ROOT_PATH + 'sslkeylogfile.txt', self.cur_packet_name.split(".")[0] + ".txt")

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

    def kill_frida(self):
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

    def get_tg_dict(self) -> dict:
        result = {}

        with open(self.ACT_TG_FILE, "r") as f:
            result.update(json.load(f))
        with open(self.ADD_TG_FILE, "r") as f:
            result.update(json.load(f))

        return result

    def get_input_from_learner(self) -> str:
        return "add_device"

    def get_output_start(self, packet_name):
        """
        Get output from packet;
        :param packet_name: The packet that is generated when the button is clicked.
        :return: output
        """
        pass

    def get_output_end(self):
        pass

    def parse_packet_and_get_response(self, packet_name) -> str:
        pass

    def response_to_learner(self, output):
        """
        Tell the learner the output of operation.
        :param output:
        :return:
        """
        pass

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

    def get_phone_conf_and_start_driver(self, conf_file):
        """
        read device.json and get config of device
        :param conf_file: path of config file
        :return: device driver for auto click
        """
        if not os.path.exists(conf_file):
            print("[ERROR] Setting device wrong, no such file: " + conf_file)
            exit(-1)
        # get config of device
        with open(conf_file) as f:
            device = json.load(f)

        self.APK_NAME = device["appPackage"]
        # check if the config file is satisfied (or not)

        # transform "" to boolean
        for item in self.bool_conf_name:
            if item in device.keys():
                if device[item].lower() == "true":
                    device[item] = True
                elif device[item].lower() == "false":
                    device[item] = False
                else:
                    print("[ERROR] Please check '" + item + "' in config/device.json")

        print("[LOG] Get device config:", device)

        driver = webdriver.Remote(self.APPIUM_IP, device)

        # command = "frida -U -F " + self.APK_NAME + " -l " + self.SCRIPTS_FOLDER + "pinning_disable.js > temp_sslpinning.txt"
        # # sslpin = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        # os.system('echo %s | sudo -S %s' % (self.admin_password, command))

        return driver

    def get_valuable_button(self, button_conf_file):
        with open(button_conf_file, "r") as f:
            valuable_button_click_path = json.load(f)

        return valuable_button_click_path


    def back_to_home(self, cur_act, driver):
        # find path
        tg_list = self.dfs_search(cur_act, self.HOME_PAGE_ACT)

        # if tg path is existing
        if tg_list:
            act_tg_dict = self.get_tg_dict()

            tg_list = tg_list[0][1:]
            for next_act in tg_list:
                xpath = act_tg_dict[cur_act][next_act]
                driver.find_element(By.XPATH, xpath).click()
                cur_act = next_act
                time.sleep(0.2)
        else:
            print("[ERROR] Can not find path from [" + cur_act + "] to [" + self.HOME_PAGE_ACT + "]")
            exit(-1)

    def click_button(self, ui_name, uip_dict, driver) -> str:
        """
        Click the button and save packets
        :param ui_name: action name that wanna be clicked
        :param uip_dict: click path dictionary of button
        :param driver: webdriver for controling app
        :return:
        """
        if ui_name not in uip_dict.keys():
            print("[ERROR] UI which will be clicked is not in config/valuable_button.json")
            exit(-1)

        # get click path
        click_path_dict = uip_dict[ui_name]
        # start collecting packets
        packet_name = self.PACKET_ROOT_PATH + ui_name + str(time.time()) + ".pcap"
        self.get_output_start(packet_name)
        # click one by one
        for index in click_path_dict.keys():
            if "description" in click_path_dict[index].keys():
                print(index + "---" + click_path_dict[index]["description"])
            else:
                print(index + "---" + ui_name + ": " + click_path_dict[index])

            # waiting for manually click
            if "waiting_time" in click_path_dict[index].keys():
                time.sleep(click_path_dict[index]["waiting_time"])

            # get location and click
            if "xpath" in click_path_dict[index].keys():
                cur_ui_xpath = click_path_dict[index]["xpath"]
                act_before = click_path_dict[index]["act_before"]
                act_after = click_path_dict[index]["act_after"]

                # if exist
                try:
                    # click
                    target = driver.find_element(By.XPATH, cur_ui_xpath)
                    if self.update_act_flag:
                        click_path_dict[index]["act_before"] = driver.current_activity
                    target.click()
                    if self.update_act_flag:
                        click_path_dict[index]["act_after"] = driver.current_activity
                except exceptions.NoSuchElementException:
                    # retry for 3 times
                    for temp_index in range(3):
                        time.sleep(5)
                        try:
                            driver.find_element(By.XPATH, cur_ui_xpath).click()
                            break
                        except exceptions.NoSuchElementException:
                            pass
                    print("[ERROR] can not find component when --- " + click_path_dict[index]["description"])
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
                    target = driver.find_element(By.ID, cur_ui_id)
                    if self.update_act_flag:
                        click_path_dict[index]["act_before"] = driver.current_activity
                    target.click()
                    if self.update_act_flag:
                        click_path_dict[index]["act_after"] = driver.current_activity
                except exceptions.NoSuchElementException:
                    # retry for 3 times
                    for temp_index in range(3):
                        time.sleep(2)
                        try:
                            driver.find_element(By.ID, cur_ui_id).click()
                            break
                        except exceptions.NoSuchElementException:
                            pass
                    print("[ERROR] can not find component when --- " + click_path_dict[index]["description"])
                    self.stop_tshark()
                    exit(-1)

            # get current activity and check
            time.sleep(0.5)  # wait for activity
            cur_activity = driver.current_activity

        # collection end
        self.get_output_end()

        # parse packet and return
        return self.parse_packet_and_get_response(packet_name)


def send_alphabet(ui_list, server_socket):
    """
    Send a reply to learner to tell the scan results.
    :param ui_list: valuable UI list
    :param server_socket: server socket to send message
    :return: response from Learner
    """
    # print log
    print("[LOG] send input_bat to learner...")
    print("input_bat---", ui_list)

    # create temp file for sending
    alphabet_file = "input_bat"
    with open(alphabet_file, "w") as f:
        for item in ui_list:
            if item != ui_list[-1]:
                f.write(item + "\n")
            else:
                f.write(item)

    # send to learner
    try:
        with open(alphabet_file, "rb") as f:
            while True:
                file_data = f.read(1024)
                if file_data:
                    server_socket.send(file_data)
                else:
                    print("[LOG] finish")
    except Exception as e:
        print("[ERROR] Send alphabet error: ", e)

    # remove temp file
    print("[LOG] remove temp file input_bat")
    os.remove(alphabet_file)


def learn_main():
    # create an entity of learn
    learn_entity = LearnCls()
    # get val_buttons
    val_but_dict = learn_entity.get_valuable_button(learn_entity.VALUABLE_BUTTON_FILE)

    # # create tcp socket and connect to server
    # print("[LOG] Start connecting to server...")
    # tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # tcp_socket.bind((learn_entity.LOCAL_IP, LOCAL_PORT))
    # tcp_socket.connect((SERVER_IP, SERVER_PORT))
    # print("[LOG] Connection build")

    # # send alphabet to learner
    # send_alphabet(list(val_but_dict.keys()), tcp_socket)

    # start app and get driver
    driver = learn_entity.get_phone_conf_and_start_driver(learn_entity.PHONE_CONF_FILE)

    # start test and get input
    learner_input = learn_entity.get_input_from_learner()

    if learner_input in val_but_dict.keys():
        if learn_entity.APK_NAME + driver.current_activity != learn_entity.HOME_PAGE_ACT:
            learn_entity.back_to_home(learn_entity.APK_NAME + driver.current_activity, driver)
        print("[LOG] Click task-----" + learner_input)
        learn_entity.start_tshark(learner_input)
        time.sleep(5)
        click_output = learn_entity.click_button(learner_input, val_but_dict, driver)
        time.sleep(5)
        learn_entity.stop_tshark()
        # learn_entity.response_to_learner(click_output)

    # if update_act_flag:
    #     # update conf
    #     with open(VALUABLE_BUTTON_FILE, "w") as f:
    #         json.dump(val_but_dict, f, indent=2)

    # close android driver and shutdown frida
    driver.quit()
    # learn_entity.kill_frida()
