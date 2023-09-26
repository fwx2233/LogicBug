"""
Scan APP to get all valuable ui compoments.
Maybe we use AppCrawler to scan ui compoments.
"""
import sys, os
import json
from xml.etree import ElementTree as et

ROOT_PATH = os.path.dirname(__file__)


def install_apk(apk_name):
    """
    Install apk to smartphone
    :param apk_name: apk under test
    """
    pass


def scan_all_ui(apk_name) -> str:
    """
    Use software to automatic click app compoments and get result
    :param apk_name: apk under test
    :return: result path
    """
    install_apk(apk_name)
    
    pass


def parse_scan_result(result_path) -> dict:
    """
    Get all the clickable UI in the app.
    :return: list:[ui_name]/dictionary:{ui_name: [click path]}
    """
    # transfer relative path to absolute path
    json_result_file = ROOT_PATH + '/' + result_path + ".json"
    result_path = ROOT_PATH + '/' + result_path + '/'
    # result
    dict_result = {}
    # get all file list
    dir_file_list = os.listdir(result_path)
    # png file list
    png_file_list = {}
    # TEST xml file list
    test_xml_file_list = []

    # get png and xml list
    for fil in dir_file_list:
        if fil.split('.')[-1] == "png" and fil.split('.')[-2] == "click":
            index_id = fil.split('_')[0]
            id_len = len(index_id) + 1
            png_file_list[index_id] = fil[id_len:]
        if fil.split('.')[-1] == "xml" and fil.split('-')[0] == "TEST":
            test_xml_file_list.append(fil)

    # parse xml
    for xml_file in test_xml_file_list:
        xml_file_path = result_path + xml_file
        tree = et.parse(xml_file_path)
        root = tree.getroot()
        test_cases = root.findall("testcase")

        for case in test_cases:
            # get property from xml file
            str_parse = case.attrib
            clicked_id = str(str_parse["name"].split()[0].split('=')[-1])
            # action = str_parse["name"].split()[1].split('=')[-1]
            xpath = str_parse["name"].split()[2][6:]
            activity = str_parse["classname"]
            # test_time = str_parse["time"]

            # save property in dict
            dict_result[clicked_id] = {}
            dict_result[clicked_id]["xpath"] = xpath
            dict_result[clicked_id]["activity"] = activity

            # get screen shot name
            if clicked_id in png_file_list.keys():
                png_name = png_file_list[clicked_id]
                dict_result[clicked_id]["png_name"] = png_name
                # remove activity property from png_name
                png_name = png_name[len(activity) + 1:-10]
                # get info from png name
                info_list = png_name.split('.')
                for info in info_list:
                    info_name = info.split('=')[0]
                    info_value = info.split('=')[-1]
                    if info_name != "" and len(info.split('=')) > 1:
                        dict_result[clicked_id][info_name] = info_value

    # save as json file
    with open(json_result_file, "w") as f:
        json.dump(dict_result, f, indent=4)

    return dict_result


def get_valuable_ui(ui_list):
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
    temp_result_path = scan_all_ui("test apk")

    # # check if the ui_list is null
    # if_terminate(ui_list)
    dict_result = parse_scan_result(temp_result_path)

    # get insteresting ui compoments
    ui_list = get_valuable_ui(ui_list)

    # check again
    if_terminate(ui_list)

    # send ui_list to learner
    send_scan_result(ui_list)