import os
import json
from appium import webdriver
from selenium.webdriver.common.by import By
from selenium.common import exceptions
from appium.webdriver.common.touch_action import TouchAction
import time
import subprocess
import signal

from learn_model import get_ips
from log import mlog
from config import device_appium_config


class DeviceCls:
    def __init__(self, scan_folder_name, device_name, which_user, distance, frida_flag=True):
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
        self.DEVICE_CONFIG_DICT = device_appium_config.get_phone_config_by_name(device_name)
        if not self.DEVICE_CONFIG_DICT:
            mlog.log_func(mlog.ERROR, "Do not have device_name: " + device_name + ". Please check your input.")
            print("Device_name list: ", device_appium_config.get_phone_list())
            exit(10)

        self.USER = which_user
        self.DISTANCE = distance
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

        # get valuable_button_dict
        self.val_but_dict = self.get_valuable_button()

        # start appium for listen
        self._start_appium_server(self.APPIUM_PATH)
        time.sleep(2)

        self.frida_flag = frida_flag
        if frida_flag:
            self._start_frida_server()
            self._write_frida_hook_bash()
            if not self.check_frida_server():
                mlog.log_func(mlog.ERROR, "frida server is not start, please check and restart")
                self._stop_appium_server()
                exit(10)
            self._start_frida_hook()
            time.sleep(2)

        # test flag and other info
        self.update_act_flag = False
        self.admin_password = "admin"
        self.cur_packet_name = ""
        self.cur_packet_folder = ""
        self.cur_packet_path = ""

    def get_valuable_button(self) -> dict:
        with open(self.VALUABLE_BUTTON_FILE, "r") as f:
            valuable_button_click_path = json.load(f)

        if self.USER not in valuable_button_click_path:
            mlog.log_func(mlog.ERROR, f"{self.USER} is not in valuable_buttion.json")
            exit(-2)

        result = dict()
        result[self.DISTANCE] = valuable_button_click_path[self.USER][self.DISTANCE]
        result["Special"] = valuable_button_click_path[self.USER]["Special"]

        return result

    def check_frida_server(self):
        fine_name = self.LOG_FOLDER_PATH + "temp_frida_ps"
        command = f'ps aux|grep "adb -s {self.UDID}" > {fine_name}'
        os.system(command)

        if os.path.exists(fine_name):
            with open(fine_name, "r") as f:
                lines = f.readlines()
            if len(lines) > 2:
                os.remove(fine_name)
                return True
            os.remove(fine_name)
            return False

    def _start_frida_server(self, frida_server_path_on_android='/data/local/tmp/'):
        mlog.log_func(mlog.LOG, f"Start frida server on phone <{self.DEVICE_NAME}>")
        command = f"bash {self.SCRIPTS_FOLDER}frida_server.sh {self.UDID} start {frida_server_path_on_android}"
        os.system(command)

    def _write_frida_hook_bash(self):
        with open(f"{self.SCRIPTS_FOLDER}/start_pinning_frida_script_{self.DEVICE_NAME}.bash", "w") as sc_file:
            sc_file.write("#!/bin/bash\n")
            sc_file.write(f'target_app="{self.APK_NAME}"\n')
            sc_file.write(f'select_device="{self.UDID}"\n')
            sc_file.write(f'script_path="{self.SCRIPTS_FOLDER}pinning_disable.js"\n')
            sc_file.write("frida -D $select_device -F $target_app -l $script_path")

    def _start_frida_hook(self):
        mlog.log_func(mlog.LOG, "Start frida to ban the SSL Pinning")
        # start disable ssl pinning
        command = "bash " + self.SCRIPTS_FOLDER + f"start_pinning_frida_script_{self.DEVICE_NAME}.bash"
        sslpin_process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stdin=open("/dev/null"))

    def _stop_frida_hook(self):
        fine_name = self.SCRIPTS_FOLDER + "temp_tshark_ps"
        command = "ps -aux|grep frida > " + fine_name
        os.system(command)
        with open(fine_name, "r") as f:
            lines = f.readlines()
        if len(lines) > 1:
            for lin in lines[:-1]:
                porc_id = lin.split()[1]
                command = "kill -9 " + porc_id
                os.system('echo %s | sudo -S %s' % (self.admin_password, command))
        os.remove(fine_name)

    def _stop_firda_server(self):
        mlog.log_func(mlog.LOG, f"Stop frida server on phone <{self.DEVICE_NAME}>")
        command = f"bash {self.SCRIPTS_FOLDER}frida_server.sh {self.UDID} shutdown fk"

    def _start_appium_server(self, path_to_appium):
        mlog.log_func(mlog.LOG, "Start appium service....")

        path = "/".join(path_to_appium.split("/")[:-1]) + ":"
        os.environ['PATH'] = path + os.environ['PATH']
        command = f"{path_to_appium} -a 127.0.0.1 -p {self.APPIUM_PORT} --session-override"
        with open(self.LOG_FOLDER_PATH + self.UDID + "_appium_log.txt", "w") as log_file:
            process = subprocess.Popen(command, stdout=log_file, stderr=subprocess.STDOUT, shell=True,
                                       preexec_fn=os.setsid)
        self.appium_process = process

    def _stop_appium_server(self):
        try:
            self.appium_process.terminate()
            time.sleep(1)
            os.killpg(os.getpgid(self.appium_process.pid), signal.SIGTERM)
            if os.path.exists(self.LOG_FOLDER_PATH + self.UDID + "_appium_log.txt"):
                os.remove(self.LOG_FOLDER_PATH + self.UDID + "_appium_log.txt")
        except ProcessLookupError:
            mlog.log_func(mlog.ERROR, "ProcessLookupError from device.stop_appium_server")

    # def parse_packet_and_get_response(self, database, packet_name, op_name, start_time, end_time) -> str:
    #     cur_key_log_file_path = f'{self.PACKET_ROOT_PATH}/sslkeylogfile_{self.DEVICE_CONFIG_DICT["additionalMess"]["identity"]}.txt'
    #     return packet_parser.get_new_op_class_for_response(database, packet_name, cur_key_log_file_path, op_name,
    #                                                        start_time, end_time)

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

    def stop_driver_and_appium_server(self):
        mlog.log_func(mlog.LOG, f"Driver <{self.DEVICE_NAME}> quit")
        if self.frida_flag:
            self._stop_frida_hook()
            self._stop_firda_server()
        self.driver.quit()
        self._stop_appium_server()

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
                mlog.log_func(mlog.ERROR, "Something wrong with frida or appium or app, can not back to home, please [restart app and restart learn]")

                # restart app
                self.stop_and_restart_app()

                from scripts import do_kill
                do_kill.kill_main()

                return False

        # back to home page
        while not self.click_button("|BackHome"):
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
        mlog.log_func(mlog.LOG, f"Click task-----<{ui_name}>")
        start_time = time.time()
        if self.click_button(ui_name):
            time.sleep(waiting_time)
            end_time = time.time()
            # save log
            # action_log_file = self.PACKET_ROOT_PATH + self.cur_packet_name.split(".")[0] + "/" + self.USER + "/" + ui_name + "/" + ui_name + '_' + str(int(start_time)) + ".txt"
            action_log_folder = self.cur_packet_folder + self.USER + "/" + ui_name.split("|")[-1] + "/"
            action_log_file = action_log_folder + ui_name + '_' + str(int(start_time)) + ".txt"
            if not os.path.exists(action_log_folder):
                os.makedirs(action_log_folder)

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
        full_ui_name = ui_name
        cur_distance = ui_name.split("|")[1]
        ui_name = ui_name.split("|")[-1]

        is_special_op = False
        if ui_name in self.val_but_dict["Special"]:
            is_special_op = True
        elif ui_name not in self.val_but_dict[cur_distance].keys():
            mlog.log_func(mlog.ERROR, f"UI <{full_ui_name}> which will be clicked is not in config/valuable_button.json")
            return False

        # get click path
        if not is_special_op:
            click_path_dict = self.val_but_dict[cur_distance][ui_name]
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
                mlog.log_func(mlog.LOG, index + "---" + full_ui_name + ": " + click_path_dict[index], t_count=1)

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
                # id_index = click_path_dict[index]["rec_index"]
                # act_before = click_path_dict[index]["act_before"]
                # act_after = click_path_dict[index]["act_after"]

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
            # cur_activity = self.driver.current_activity

        return True

    def pull_to_refresh(self):
        mlog.log_func(mlog.LOG, "Refresh at homepage")
        # get window size
        window_size = self.driver.get_window_size()
        width = window_size['width']
        height = window_size['height']

        # define start point and end point
        start_x = width / 2
        start_y = height / 4
        end_x = start_x
        end_y = height * 3 / 4

        self.driver.swipe(start_x, start_y, end_x, end_y, 500)
        time.sleep(0.5)

    def set_packet_name(self, pcap_name):
        self.cur_packet_name = pcap_name
        self.cur_packet_folder = self.PACKET_ROOT_PATH + "_".join(self.cur_packet_name.split("_")[:-1]) + "/" + self.cur_packet_name.split("_")[-1][:-7] + "/"
        self.cur_packet_path = self.cur_packet_folder + pcap_name


if __name__ == "__main__":
    # pixel7_entity = DeviceCls("20230920183445_com.huawei.smarthome", "pixel7", "user1", frida_flag=True)
    pixel62_entity = DeviceCls("20230920183445_com.huawei.smarthome", "pixel6-2", "user2", distance="local", frida_flag=False)
    pixel62_entity.start_driver_and_init()


    def pull_to_refresh(driver):
        # 获取屏幕尺寸
        window_size = driver.get_window_size()
        width = window_size['width']
        height = window_size['height']

        # 定义滑动起始点和终点
        # define start point and end point
        start_x = width / 2
        start_y = height / 4
        end_x = start_x
        end_y = height * 3 / 4

        driver.swipe(start_x, start_y, end_x, end_y, 500)

    try:
        pull_to_refresh(pixel62_entity.driver)
        pixel62_entity.click_button("user2|local|DeviceControl")
    except:
        print("Error")

    pixel62_entity.stop_driver_and_appium_server()
