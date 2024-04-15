appium_path = "/home/ubuntu1604/.nvm/versions/node/v12.22.12/bin/appium"

phone_configs = {
    "nexus": {
        # guest remote
        "platformName": "Android",
        "deviceName": "nexus",
        "appPackage": "com.huawei.smarthome",
        "appActivity": ".login.LauncherActivity",
        "udid": "5VT7N15A29000275",
        "noReset": True,
        "dontStopAppOnReset": True,
        'newCommandTimeout': "600",
        "additionalMess": {
            "homePage": "com.huawei.smarthome.activity.MainActivity",
            "wirelessCard": "wlxaca2132b3483",
            "port": 4723,
            "appium_ip": "http://127.0.0.1:4723/wd/hub",
            "phone_ip": "10.42.1.15",
            "distance": "remote",
            "user": "user2"
        }
    },
    "pixel7": {
        # host local
        "platformName": "Android",
        "deviceName": "pixel7",
        "appPackage": "com.huawei.smarthome",
        "appActivity": ".login.LauncherActivity",
        "udid": "2A111FDH200CJ3",
        "noReset": True,
        "dontStopAppOnReset": True,
        'newCommandTimeout': "600",
        "additionalMess": {
            "homePage": "com.huawei.smarthome.activity.MainActivity",
            "wirelessCard": "wlxc01c30151c62",
            "port": 4724,
            "appium_ip": "http://127.0.0.1:4724/wd/hub",
            "phone_ip": "10.42.0.230",
            "distance": "local",
            "user": "user1"
        }
    },
    "pixel6-1": {
        # host remote
        "platformName": "Android",
        "deviceName": "pixel6-1",
        "appPackage": "com.huawei.smarthome",
        "appActivity": ".login.LauncherActivity",
        "udid": "1C071FDF60020H",
        "noReset": True,
        "dontStopAppOnReset": True,
        'newCommandTimeout': "600",
        "additionalMess": {
            "homePage": "com.huawei.smarthome.activity.MainActivity",
            "wirelessCard": "wlxaca2132b3483",
            "port": 4725,
            "appium_ip": "http://127.0.0.1:4725/wd/hub",
            "phone_ip": "10.42.1.163",
            "distance": "remote",
            "user": "user1"
        }
    },
    "pixel6-2": {
        # guest local
        "platformName": "Android",
        "deviceName": "pixel6-2",
        "appPackage": "com.huawei.smarthome",
        "appActivity": ".login.LauncherActivity",
        "udid": "26151FDF6005FT",
        "noReset": True,
        "dontStopAppOnReset": True,
        'newCommandTimeout': "600",
        "additionalMess": {
            "homePage": "com.huawei.smarthome.activity.MainActivity",
            "wirelessCard": "wlxc01c30151c62",
            "port": 4726,
            "appium_ip": "http://127.0.0.1:4726/wd/hub",
            "phone_ip": "10.42.0.66",
            "distance": "local",
            "user": "user2"
        }
    }
}

device_ip_list = [
    "10.42.0.185"
]


def get_phone_config_by_name(device_name):
    if device_name in phone_configs:
        return phone_configs[device_name]
    return False


def get_phone_list():
    return list(phone_configs.keys())


def get_phone_and_device_ip():
    result_dict = {}
    for phone in phone_configs:
        ip = phone_configs[phone]["additionalMess"]["phone_ip"]
        user = phone_configs[phone]["additionalMess"]["user"]
        distance = phone_configs[phone]["additionalMess"]["distance"]

        if user not in result_dict:
            result_dict[user] = {}
        result_dict[user][distance] = ip

    # add device ip list
    result_dict["devices"] = device_ip_list

    return result_dict


if __name__ == "__main__":
    print(get_phone_and_device_ip())
