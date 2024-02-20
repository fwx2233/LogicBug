import os
import subprocess

ROOT_PATH = os.path.dirname(__file__)

def check_if_frida_server_is_start():
    fine_name = ROOT_PATH + "/temp_frida_ps"
    command = 'ps aux|grep "adb shell" > ' + fine_name
    os.system(command)

    if os.path.exists(fine_name):
        with open(fine_name, "r") as f:
            lines = f.readlines()
        if len(lines) > 2:
            return True
        return False


if __name__ == "__main__":
    check_if_frida_server_is_start()
