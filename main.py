"""
Main
"""
from learn_model import learn
from analyse_app import analyse


def start_main():
    print("[LOG] Welcome!!! Testing program is come to start now")

    print("[LOG] Start analysing appcrawler result")
    scan_folder_name = analyse.analyse_main("com.huawei.smarthome")

    print("[LOG] Start learn model")
    learn.learn_main(scan_folder_name)


if __name__ == "__main__":
    start_main()
