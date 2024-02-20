import subprocess
import os


ROOT_PATH = os.path.dirname(__file__)


def get_pid_and_username(apk_name):
    """
    Retrieve the PID and running username of the package named 'apk_name' when running on a mobile phone
    :param apk_name: apk_name, such as: com.x.y
    :return: pid_list->list, username->str
    """
    ps_file = ROOT_PATH + "/temp_ps.txt"
    command = "adb shell ps |grep " + apk_name + " > " + ps_file
    # temp_proc = subprocess.Popen(command.split())
    os.system(command)

    username = None
    pid_list = []
    with open(ps_file, "r") as file:
        temp = file.readlines()
        for line in temp:
            username = line.split()[0]
            pid_list.append(line.split()[1])

    os.remove(ps_file)

    return pid_list, username


def get_ips_by_username(username):
    """
    Retrieve all IP addresses accessed by username.
    :param username: username
    :return:[ip_list]
    """
    output_file = ROOT_PATH + "/output.txt"
    command = "adb shell netstat -e |grep " + username + " > " + output_file
    os.system(command)

    ip_list = []
    with open(output_file, "r") as file:
        lines = file.readlines()
        for line in lines:
            if ":" in line.split()[4].split(".")[0]:
                continue
            cur_ip = ".".join(line.split()[4].split(".")[0].split("-")[1:])
            if cur_ip:
                ip_list.append(cur_ip)

    os.remove(output_file)
    ip_list = list(set(ip_list))
    return ip_list


def get_ips_by_pid(pid):
    """
    Retrieve all IP addresses accessed by PID.
    :param pid: PID
    :return: [ip_list]
    """
    output_file = ROOT_PATH + "/output.txt"
    command = "adb shell netstat -nlp |grep " + pid + " > " + output_file
    os.system(command)

    ip_list = []
    with open(output_file, "r") as file:
        lines = file.readlines()
        for line in lines:
            if ":" in line.split()[4].split(".")[0]:
                continue
            cur_ip = ".".join(line.split()[4].split(".")[0].split("-")[1:])
            if cur_ip:
                ip_list.append(cur_ip)

    os.remove(output_file)
    ip_list = list(set(ip_list))
    return ip_list


def get_ips_by_pid_list(pid_list):
    """
    Retrieve all IP addresses accessed by PID.
    :param pid_list: list of PID
    :return: {pid: [ip_list]}
    """
    pid_ip_dict = {}
    for pid in pid_list:
        pid_ip_dict[pid] = get_ips_by_pid(pid)

    return pid_ip_dict


def merge_manual_ip_list(ip_list_by_script: list):
    """
    Merge manual ip config list which is interesting
    :param ip_list_by_script: ip list got by netstat
    :return: merged ip list
    """
    manual_file = ROOT_PATH + "/../config/interesting_ip_list.txt"
    with open(manual_file, "r") as f:
        lines = f.readlines()
        for line in lines:
            new_ip = line.replace("\n", "")
            if new_ip and new_ip not in ip_list_by_script:
                ip_list_by_script.append(new_ip)
    ip_list_by_script = sorted(list(set(ip_list_by_script)))

    with open(manual_file, "w") as f:
        for item in ip_list_by_script:
            f.write(item + "\n")

    return ip_list_by_script


def generate_filter_condition_by_ip_list(ip_list):
    """
    Generate filter conditions by ip list, such as "(ip.addr == ip1) or (ip.addr == ip2)"
    :param ip_list: [ip1, ip2]
    :return: condition result -> str
    """
    result_condition = "("
    for index in range(len(ip_list)):
        result_condition += "(ip.addr == " + ip_list[index] + ")"
        if index != len(ip_list) - 1:
            result_condition += " or "
    result_condition += " or udp)"
    # result_condition += ")"
    return result_condition


def get_and_save_ip_list_by_apk(apk_name):
    pid_list, username = get_pid_and_username(apk_name)
    ip_list = get_ips_by_username(username)
    ip_list = merge_manual_ip_list(ip_list)

    return ip_list


if __name__ == "__main__":
    test_apk_name = "com.huawei.smarthome"
    pid_list, username = get_pid_and_username(test_apk_name)
    ip_list = get_ips_by_username(username)
    ip_list = merge_manual_ip_list(ip_list)
    condition = generate_filter_condition_by_ip_list(ip_list)
    print(condition)
