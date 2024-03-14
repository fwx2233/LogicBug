appium_path = "/home/ubuntu1604/.nvm/versions/node/v12.22.12/bin/appium"

phone_configs = {
    "nexus": {
        # owner---local control and add device
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
            "wirelessCard": "wlxc01c302ff1cf",
            "port": 4723,
            "appium_ip": "http://127.0.0.1:4723/wd/hub",
            "phone_ip": "10.42.1.15",
            "distance": "remote"
        }
    },
    "pixel7": {
        # guest
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
            "distance": "local"
        }
    }
}

device_ip_list = [
    "10.42.0."
]


def get_phone_config_by_name(device_name):
    if device_name in phone_configs:
        return phone_configs[device_name]
    return False


def get_phone_list():
    return list(phone_configs.keys())
