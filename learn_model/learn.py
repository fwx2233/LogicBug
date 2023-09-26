"""
Learn APP's model
"""
import os, json

ROOT_PATH = os.path.dirname(__file__)
PACKET_ROOT_PATH = ROOT_PATH + "/packets/"
LOG_FILE = ROOT_PATH + "/../analyse_app/temp_scan_result/act_tg.json"


def save_packet(packet, file_name):
    """
    Save the packet when the corresponding button is clicked for fuzzing.
    :param packet: The packet that is generated when the button is clicked.
    :param file_name:
    :return:
    """
    pass


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
    def searchGraph(graph,start,end):
        results = []
        generatePath(graph,[start],end,results)
        results.sort(key=lambda x:len(x))
        return results

    def generatePath(graph,path,end,results):
        state = path[-1]
        if state == end:
            results.append(path)
        else:
            for arc in graph[state]:
                if arc not in path:
                    generatePath(graph,path + [arc],end,results)

    act_tg_dict = {}
    with open(LOG_FILE, "r") as f:
        act_tg_dict = json.load(f)

    # print(act_tg_dict)
    for nodes in act_tg_dict.keys():
        act_tg_dict[nodes] = list(act_tg_dict[nodes].keys())
    
    r = searchGraph(act_tg_dict, act1, act2)

    if not r:
        return []
    else:
        return r[0]
    


def click_button(ui_name, uip_list):
    """
    Click the button and save packets
    :param ui_name:
    :param uip_list:
    :return:
    """
    pass


def learn_main():
    act1 = "com.huawei.smarthome.HomeListActivity"
    act2 = "com.huawei.smarthome.ScoreTasksActivity"
    print(dfs_search(act1, act2))
    pass