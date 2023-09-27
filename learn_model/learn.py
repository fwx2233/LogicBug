"""
Learn APP's model
"""
import os
import json
from appium import webdriver
from selenium.webdriver.common.by import By
import time

ROOT_PATH = os.path.dirname(__file__)
PACKET_ROOT_PATH = ROOT_PATH + "/packets/"
ACT_TG_FILE = ROOT_PATH + "/../analyse_app/temp_scan_result/act_tg.json"
CONF_FOLDER_PATH = ROOT_PATH + "/../config/"
PHONE_CONF_FILE = CONF_FOLDER_PATH + "device.json"
APPIUM_IP = "http://127.0.0.1:4723/wd/hub"
VALUABLE_BUTTON_FILE = CONF_FOLDER_PATH + "valuable_button.json"

bool_conf_name = ["noReset", "dontStopAppOnReset"]


def save_packet(packet, file_name):
    """
    Save the packet when the corresponding button is clicked for fuzzing.
    :param packet: The packet that is generated when the button is clicked.
    :param file_name:
    :return:
    """
    pass


def get_input_from_learner() -> str:
    return "Add Scene"


def get_output(packet) -> str:
    """
    Get output from packet;
    :param packet: The packet that is generated when the button is clicked.
    :return: output
    """
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
    def search_graph(graph,start,end):
        results = []
        generate_path(graph, [start], end, results)
        results.sort(key=lambda x: len(x))
        return results

    def generate_path(graph,path,end,results):
        state = path[-1]
        if state == end:
            results.append(path)
        else:
            for arc in graph[state]:
                if arc not in path:
                    generate_path(graph, path + [arc], end, results)

    act_tg_dict = {}
    with open(ACT_TG_FILE, "r") as f:
        act_tg_dict = json.load(f)

    # print(act_tg_dict)
    for nodes in act_tg_dict.keys():
        act_tg_dict[nodes] = list(act_tg_dict[nodes].keys())
    
    r = search_graph(act_tg_dict, act1, act2)

    if not r:
        return []
    else:
        return r


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


def click_button(ui_name, uip_dict, driver):
    """
    Click the button and save packets
    :param ui_name:
    :param uip_dict:
    :param driver:
    :return:
    """
    if ui_name not in uip_dict.keys():
        print("[ERROR] UI which will be clicked is not in config/valuable_button.json")
    click_path_dict = uip_dict[ui_name]
    for index in click_path_dict.keys():
        print(index, click_path_dict[index])
        if "xpath" in click_path_dict[index].keys():
            cur_ui_xpath = click_path_dict[index]["xpath"]
            cur_ui_activity = click_path_dict[index]["activity"]
            # click with xpath
            driver.find_element(By.XPATH, cur_ui_xpath).click()
        elif "resource_id" in click_path_dict[index].keys():
            cur_ui_id = click_path_dict[index]["resource_id"]
            id_index = click_path_dict[index]["rec_index"]
            # click with resource_id
            driver.find_element(By.ID, cur_ui_id).click()
            # check if cur activity is correct


def learn_main():
    driver = get_phone_conf_and_start_driver(PHONE_CONF_FILE)
    val_but = get_valuable_button(VALUABLE_BUTTON_FILE)

    learner_input = get_input_from_learner()
    if learner_input in get_input_from_learner():
        print("[LOG] Click button---", learner_input)
        click_button(learner_input, val_but, driver)
        time.sleep(0.2)
