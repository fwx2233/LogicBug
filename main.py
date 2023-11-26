"""
Main
"""
from learn_model import learn
from analyse_app import analyse
from log import mlog


def start_main():
    mlog.clear_log()
    mlog.log_func(mlog.LOG, "Welcome!!! Testing program is come to start now")

    mlog.log_func(mlog.LOG, "Start analysing appcrawler result")
    scan_folder_name = analyse.analyse_main("com.huawei.smarthome")

    mlog.log_func(mlog.LOG, "Start learn model")
    learn.learn_main(scan_folder_name)


if __name__ == "__main__":
    start_main()
