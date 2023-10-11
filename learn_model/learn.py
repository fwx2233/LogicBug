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

ROOT_PATH = os.path.dirname(__file__)
PACKET_ROOT_PATH = ROOT_PATH + "/packets/"
ACT_TG_FILE = ROOT_PATH + "/../analyse_app/temp_scan_result/act_tg.json"
ADD_TG_FILE = ROOT_PATH + "/../analyse_app/temp_scan_result/additional_tg.json"
CONF_FOLDER_PATH = ROOT_PATH + "/../config/"
PHONE_CONF_FILE = CONF_FOLDER_PATH + "device.json"
APPIUM_IP = "http://127.0.0.1:4723/wd/hub"
VALUABLE_BUTTON_FILE = CONF_FOLDER_PATH + "valuable_button.json"
HOME_PAGE_ACT = "com.huawei.smarthome.activity.MainActivity"
APK_NAME = ""

LOCAL_IP = ""
LOCAL_PORT = 7009
SERVER_IP = "192.168.50.206"
SERVER_PORT = 7009

bool_conf_name = ["noReset", "dontStopAppOnReset"]
update_act_flag = False


def save_packet(packet, file_name):
    """
    Save the packet when the corresponding button is clicked for fuzzing.
    :param packet: The packet that is generated when the button is clicked.
    :param file_name:
    :return:
    """
    pass


def get_tg_dict() -> dict:
    result = {}

    with open(ACT_TG_FILE, "r") as f:
        result.update(json.load(f))
    with open(ADD_TG_FILE, "r") as f:
        result.update(json.load(f))

    return result


def get_input_from_learner() -> str:
    return "add_device"


def get_output_start(packet_name):
    """
    Get output from packet;
    :param packet_name: The packet that is generated when the button is clicked.
    :return: output
    """
    pass


def get_output_end():
    pass


def parse_packet_and_get_response(packet_name) -> str:
    pass


def response_to_learner(output):
    """
    Tell the learner the output of operation.
    :param output:
    :return:
    """
    pass


def dfs_search(act1, act2):
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

    act_tg_dict = get_tg_dict()

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


def get_phone_conf_and_start_driver(conf_file):
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

    global APK_NAME
    APK_NAME = device["appPackage"]
    # check if the config file is satisfied (or not)

    # transform "" to boolean
    for item in bool_conf_name:
        if item in device.keys():
            if device[item].lower() == "true":
                device[item] = True
            elif device[item].lower() == "false":
                device[item] = False
            else:
                print("[ERROR] Please check '" + item + "' in config/device.json")

    print("[LOG] Get device config:", device)

    driver = webdriver.Remote(APPIUM_IP, device)
    return driver


def get_valuable_button(button_conf_file):
    with open(button_conf_file, "r") as f:
        valuable_button_click_path = json.load(f)

    return valuable_button_click_path


def back_to_home(cur_act, driver):
    # find path
    tg_list = dfs_search(cur_act, HOME_PAGE_ACT)

    # if tg path is existing
    if tg_list:
        act_tg_dict = get_tg_dict()

        tg_list = tg_list[0][1:]
        for next_act in tg_list:
            xpath = act_tg_dict[cur_act][next_act]
            driver.find_element(By.XPATH, xpath).click()
            cur_act = next_act
            time.sleep(0.2)
    else:
        print("[ERROR] Can not find path from [" + cur_act + "] to [" + HOME_PAGE_ACT + "]")
        exit(-1)


def click_button(ui_name, uip_dict, driver) -> str:
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
    packet_name = PACKET_ROOT_PATH + ui_name + str(time.time()) + ".pcap"
    get_output_start(packet_name)
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
                if update_act_flag:
                    click_path_dict[index]["act_before"] = driver.current_activity
                target.click()
                if update_act_flag:
                    click_path_dict[index]["act_after"] = driver.current_activity
            except exceptions.NoSuchElementException:
                # retry for 3 times
                for temp_index in range(3):
                    time.sleep(2)
                    try:
                        driver.find_element(By.XPATH, cur_ui_xpath).click()
                        break
                    except exceptions.NoSuchElementException:
                        pass
                print("[ERROR] can not find component when --- " + click_path_dict[index]["description"])
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
                if update_act_flag:
                    click_path_dict[index]["act_before"] = driver.current_activity
                target.click()
                if update_act_flag:
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
                exit(-1)

        # get current activity and check
        time.sleep(0.5)  # wait for activity
        cur_activity = driver.current_activity

    # collection end
    get_output_end()

    # parse packet and return
    return parse_packet_and_get_response(packet_name)


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
    # # get val_buttons
    # val_but_dict = get_valuable_button(VALUABLE_BUTTON_FILE)

    # # create tcp socket and connect to server
    # print("[LOG] Start connecting to server...")
    # tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # tcp_socket.bind((LOCAL_IP, LOCAL_PORT))
    # tcp_socket.connect((SERVER_IP, SERVER_PORT))
    # print("[LOG] Connection build")
    #
    # # send alphabet to learner
    # send_alphabet(list(val_but_dict.keys()), tcp_socket)

    ## start app and get driver
    # driver = get_phone_conf_and_start_driver(PHONE_CONF_FILE)
    #
    # # start test and get input
    # learner_input = get_input_from_learner()
    # # print("[LOG] Testing list: ", learner_input)
    #
    # if learner_input in val_but_dict.keys():
    #     if APK_NAME + driver.current_activity != HOME_PAGE_ACT:
    #         back_to_home(APK_NAME + driver.current_activity, driver)
    #     print("[LOG] Click task-----" + learner_input)
    #     click_output = click_button(learner_input, val_but_dict, driver)
    #     response_to_learner(click_output)
    #
    # if update_act_flag:
    #     # update conf
    #     with open(VALUABLE_BUTTON_FILE, "w") as f:
    #         json.dump(val_but_dict, f, indent=2)

    # # close android driver
    # driver.quit()

    '''
        test
    '''

