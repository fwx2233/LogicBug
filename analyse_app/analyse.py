"""
Scan APP to get all valuable ui compoments.
Maybe we use AppCrawler to scan ui compoments.
"""
import sys


def scan_all_ui() -> list:
    """
    Get all the clickable UI in the app.
    :return: list:[ui_name]/dictionary:{ui_name: [click path]}
    """
    pass


def get_valuable_ui(ui_list) -> list:
    """
    Get valuable UI from all UI list.
    :param ui_list: all UI list/dictionary
    :return: valuable UI list/dictionary
    """
    pass


def send_scan_result(ui_list):
    """
    Send a reply to Learner to tell the scan results.
    :param ui_list: valuable UI list
    :return: response from Learner
    """
    pass


def if_terminate(ui_list):
    """
    When input is none, terminate the program.
    :param ui_list:
    :return:
    """
    if len(ui_list) == 0:
        print("-------------------------------------------------")
        print("[-] No UI has been scanned from APP, program stop")
        print("-------------------------------------------------")
        sys.exit(0)
    else:
        pass


def analyse_main():
    # scan all ui compoments
    ui_list = scan_all_ui()

    # check if the ui_list is null
    if_terminate(ui_list)

    # get insteresting ui compoments
    ui_list = get_valuable_ui(ui_list)

    # check again
    if_terminate(ui_list)

    # send ui_list to learner
    send_scan_result(ui_list)