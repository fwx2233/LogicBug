import json
import pyshark
import os
import csv
from collections import defaultdict
from collections import OrderedDict

from learn_model import format_tools, get_ips
from log import mlog
from learn_model.protocol_feature import feature_dict

ROOT_PATH = os.path.dirname(__file__)
PACKET_ROOT_PATH = ROOT_PATH + "/packets/"

FILTER_CONDITION = "((http or mqtt or ((udp and !dns) and (udp and !mdns))) and !bootp and !coap)"
merged_ip_list = get_ips.merge_manual_ip_list([])
condition_sentence = get_ips.generate_filter_condition_by_ip_list(merged_ip_list)
FILTER_CONDITION = FILTER_CONDITION + " and " + condition_sentence

specific_response_flag = True
specific_response_op_name_list = ["ADU1CWR"]

# similarity threshold of documents. if larger than similarity_threshold, regard as the same word
threshold_among_each_kind_of_operation = 0.5
threshold_in_one_op = 0.85

not_feature_list = feature_dict["record"]
protocol_to_be_filtered = ["http", "udp"]

disabled_words = ["HTTP response", "Group:", "Date:", "Request:", "Response:", " in frame:", "Time since request:",
                  "Prev ", "prev_", "HTTP request", "Severity level:", "Expert Info ", "Status Code Description:",
                  "request_number:", "request_in:", "response_number:"]

fieldnames_of_csv = []
for protocol_name in feature_dict.keys():
    fieldnames_of_csv.extend(feature_dict[protocol_name])
ori_len_of_fieldnames = len(fieldnames_of_csv)


def get_highest_except_segments_layer_name(packet):
    """
    get the highest layer from packet, without ssl.segment
    """
    ori_layer_list = str(packet.layers).replace("[<", "").replace(">]", "").lower().split(">, <")
    for temp_index in range(len(ori_layer_list) - 1, -1, -1):
        if "segments" in ori_layer_list[temp_index]:
            pass
        else:
            return ori_layer_list[temp_index].split()[0]


def get_phone_ips():
    from config.device_appium_config import device_configs
    ips = []
    for phone, conf in device_configs.items():
        ip = conf["additionalMess"]["phone_ip"]
        if ip not in ips:
            ips.append(ip)
    return ips


def save_feature_in_csv_file(feature_list, csv_path):
    """
    :param feature_list:
    :param csv_path: path to csv file
    """
    with open(csv_path, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames_of_csv)
        writer.writeheader()
        writer.writerows(feature_list)


def get_header_features(pcap: pyshark.FileCapture, pcapng_file_name: str, dns_mapping_list: list, **save_file_param)-> list:
    """
    For a given pcap file, extract the features of all headers
    :param pcap: Given pcap file
    :param pcapng_file_name: The name of pcapng file, such as manually.pcapng
    :param dns_mapping_list: Map ip addresses to domain names
    :param blackname_dict: Blacklist list of doain and ip. Content appearing in this list will not be considered as feature
    :param save_file_param: save_csv_flag:bool, op_file_name:str such as INVITE.txt, save_payload_flag:bool
    :return : header feature list
    """
    pcap_feature_dict_list = []
    packet_num = 0
    merge_flag = False
    for packet in pcap:
        packet_feature_dict = {}
        # get basic info
        if "ip" not in packet:
            mlog.log_func(mlog.ERROR, "packet " + str(packet.number) + " do not have ip layer")
            exit(2)
        packet_feature_dict["number"] = packet.number
        packet_feature_dict["src"] = packet.ip.src
        packet_feature_dict["dst"] = packet.ip.dst
        packet_feature_dict["domain"] = format_tools.get_domain_by_ip(packet.ip.dst, dns_mapping_list)

        if packet.ip.src not in get_phone_ips():
            packet_feature_dict["srcport"] = packet[packet.transport_layer].srcport
        else:
            packet_feature_dict["srcport"] = None
        if packet.ip.dst not in get_phone_ips():
            packet_feature_dict["dstport"] = packet[packet.transport_layer].dstport
        else:
            packet_feature_dict["dstport"] = None
        if "save_payload_flag" in save_file_param and save_file_param["save_payload_flag"]:
            packet_feature_dict["payload"] = format_tools.remove_string_by_some_pattern(get_payload_from_packet(packet))

        # get features for each protocol
        for protocol_name in feature_dict.keys():
            if protocol_name in ["record", "common"]:
                continue
            if protocol_name in packet:
                packet_feature_dict["protocol"] = protocol_name
                cur_layer = packet[protocol_name]
                for field_name in feature_dict[protocol_name]:
                    if field_name in cur_layer.field_names:
                        result_str = format_tools.simply_format_header_feature(cur_layer.get_field(field_name))
                        packet_feature_dict[field_name] = result_str
                    else:
                        packet_feature_dict[field_name] = None

                # if this packet is the response of any http packet
                if "response" in cur_layer.field_names and "request_in" in cur_layer.field_names:
                    # merge this response to request(http)
                    # find the request of this response
                    for index in range(len(pcap_feature_dict_list) - 1, -1, -1):
                        if pcap_feature_dict_list[index]["number"] == cur_layer.request_in:
                            pcap_feature_dict_list[index]["response_number"] = packet_feature_dict["number"]
                            if "save_payload_flag" in save_file_param and save_file_param["save_payload_flag"]:
                                pcap_feature_dict_list[index]["payload"] = packet_feature_dict["payload"]
                            merge_flag = True
                            break

            else:
                for field_name in feature_dict[protocol_name]:
                    packet_feature_dict[field_name] = None

        if not merge_flag:
            pcap_feature_dict_list.append(packet_feature_dict)
            packet_num += 1

        merge_flag = False

    # if save_csv_flag:
    if "save_csv_flag" in save_file_param and save_file_param["save_csv_flag"]:
        if "op_file_name" in save_file_param:
            if "save_payload_flag" in save_file_param:
                fieldnames_of_csv.insert(0, "payload")
            # save csv file
            csv_file_path = PACKET_ROOT_PATH + pcapng_file_name.split(".")[0] + "/" + save_file_param["op_file_name"].split("_")[0] + "/" + save_file_param["op_file_name"].split(".")[0] + ".csv"
            save_feature_in_csv_file(pcap_feature_dict_list, csv_file_path)

            if "save_payload_flag" in save_file_param:
                fieldnames_of_csv.pop(0)
        else:
            mlog.log_func(mlog.ERROR, "Parameter \"op_file_name\" is missing, could not save in csv file")

    return pcap_feature_dict_list


def get_payload_from_packet(packet):
    highest_layer_name = get_highest_except_segments_layer_name(packet)
    return_str = None

    # udp
    if "udp" in packet:
        if highest_layer_name == "data":
            ascii_str_list = str(packet.data.data)
            if ":" in ascii_str_list:
                ascii_str_list = ascii_str_list.split(":")

            return_str = ":".join(ascii_str_list)
            return return_str

    # tcp
    if "tcp" in packet:
        # http
        if "http" in packet:
            # with file_data
            if "file_data" in packet.http.field_names:
                return_str = packet.http.file_data
            else:
                # just with return code
                if "response_code" in packet.http.field_names:
                    return_str = packet.http.response_code
                else:
                    sorted_http_field_names = sorted(packet.http.field_names)
                    if len(sorted_http_field_names[0].split()) > 1:
                        return_str = sorted_http_field_names[0].split()[1]
                    else:
                        return_str = sorted_http_field_names[0]
        # mqtt
        if "mqtt" in packet:
            mqtt_layer = packet.mqtt
            field_names = sorted(mqtt_layer.field_names)
            if "msg" in field_names:
                # return str(mqtt_layer.msg)
                return_str = mqtt_layer.msg
            else:
                mqtt_info = {}
                for field in field_names:
                    if "len" not in field and "msgid" not in field:
                        mqtt_info[field] = mqtt_layer._get_internal_field_by_name(field)
                return_str = mqtt_info

    if return_str:
        return format_tools.remove_string_by_some_pattern(str(return_str))
    else:
        return "payload_is_None"


def split_list_by_length(strings):
    length_dict = defaultdict(list)

    for temp_index in range(len(strings)):
        if strings[temp_index]:
            str_split_list = strings[temp_index].split(",")
            split_len_list = [str(len(item)) for item in str_split_list]
            length = "|".join(split_len_list)
            # length = len(strings[temp_index])
            length_dict[length].append(strings[temp_index])
        else:
            length_dict['0'].append(strings[temp_index])

    result = list(length_dict.values())

    for i in range(len(result)):
        result[i] = list(set(result[i]))

    return result


def get_dataset_name_list():
    return_list = []
    all_file_list = os.listdir(PACKET_ROOT_PATH)
    for item in all_file_list:
        if "_" in item and os.path.isdir(PACKET_ROOT_PATH + item):
            return_list.append(item)

    return return_list


def parse_dns_and_get_ip_domain(pcapng_file_name, keep_file_flag=True):
    """
    Parse the packet about the DNS in the given pcapng file and get a mapping of the ip-domain name
    :param pcapng_file_name: packet under parsing
    :return : mapping list
    """
    # mlog.log_func(mlog.LOG, "Parsing DNS...")
    dns_mapping_list = []

    def parse_dns_response(dns_layer):
        cur_mapping = {}
        reflect_cname_mapping = {}
        count_answers = int(dns_layer.count_answers)
        dns_layer = str(dns_layer).replace("\t", "").split("\n")
        if "Answers" in dns_layer:
            start_index = dns_layer.index("Answers") + 1
            for item in dns_layer[start_index: start_index + count_answers]:
                domain = item.split(":")[0]
                result = item.split()[-1]
                if "CNAME" in item:
                    # cur_mapping[domain] = result
                    reflect_cname_mapping[result] = domain
                elif 'A' in item:
                    # if domain not in cur_mapping:
                    #     cur_mapping[domain] = []
                    # cur_mapping[domain].append(result)
                    cur_mapping[result] = domain
            for ip in cur_mapping:
                while cur_mapping[ip] in reflect_cname_mapping:
                    cur_mapping[ip] = reflect_cname_mapping[cur_mapping[ip]]

        return cur_mapping

    pcapng_file_path = PACKET_ROOT_PATH + pcapng_file_name.split(".")[0] + "/" + pcapng_file_name
    cap = pyshark.FileCapture(pcapng_file_path, display_filter="dns")
    for packet in cap:
        if "dns" not in dir(packet):
            continue
        if 'resp_name' in packet.dns.field_names:
            dns_layer = packet.dns
            parse_result = parse_dns_response(dns_layer)
            if parse_result not in dns_mapping_list:
                dns_mapping_list.append(parse_result)
    cap.close()

    # if using history record
    if keep_file_flag:
        total_dict = dict()
        for dns_item in dns_mapping_list:
            for key, value in dns_item.items():
                total_dict[key] = value

        dns_mapping_file_path = ROOT_PATH + "/../config/dns_mapping.json"
        if os.path.exists(dns_mapping_file_path) and os.path.getsize(dns_mapping_file_path):
            with open(dns_mapping_file_path, "r") as dns_file_handle:
                history_dns_record = json.load(dns_file_handle)
            for key, value in total_dict.items():
                history_dns_record[key] = value
            with open(dns_mapping_file_path, "w") as dns_file_handle:
                dns_file_handle.write(json.dumps(history_dns_record, indent=4))
            return history_dns_record

        else:
            with open(dns_mapping_file_path, "w") as dns_file_handle:
                dns_file_handle.write(json.dumps(total_dict, indent=4))
            return total_dict
    else:
        return dns_mapping_list


def get_key_from_uri(uri_str):
    return "|".join([str(len(x)) for x in uri_str.split("/")])


def get_url_pattern(dataset, threshold=0.5) -> dict:
    """
    get http-url pattern for dataset
    :param dataset: dataset
    :param threshold: When the number of changes exceeds the <threshold>, the part is considered to be abstracted
    :return: pattern dictionary
    """
    result_dict = {}
    dataset_path = PACKET_ROOT_PATH + dataset + "/"
    operation_folders = os.listdir(dataset_path)

    for op in operation_folders:
        if not os.path.isdir(dataset_path + op):
            continue
        op_folder_path = dataset_path + op + "/"
        file_list = os.listdir(op_folder_path)

        # read from csv files
        for file in file_list:
            if op not in file or file.split(".")[-1] != "csv":
                continue
            with open(op_folder_path + file, "r") as f_handle:
                reader = csv.reader(f_handle)
                header = next(reader)
                domain_index = list(header).index("domain")
                uri_index = list(header).index("request_uri")
                for line in list(reader):
                    if line[uri_index] and line[domain_index]:
                        if line[domain_index] not in result_dict:
                            result_dict[line[domain_index]] = {}
                        format_uri_key = get_key_from_uri(line[uri_index])
                        if format_uri_key not in result_dict[line[domain_index]]:
                            result_dict[line[domain_index]][format_uri_key] = []
                        if line[uri_index] not in result_dict[line[domain_index]][format_uri_key]:
                            result_dict[line[domain_index]][format_uri_key].append(line[uri_index])

    pattern_dict = {}
    # get uri pattern
    for domain in result_dict.keys():
        for key, uri_list in result_dict[domain].items():
            new_pattern_list = format_tools.get_patterns_for_cases(uri_list)
            record_flag = False
            for pattern_index in range(len(new_pattern_list)):
                pattern_str = "".join(new_pattern_list[pattern_index])
                if "Abs_Len" in pattern_str:
                    record_flag = True
            if record_flag:
                # add to pattern dictionary
                if domain not in pattern_dict:
                    pattern_dict[domain] = dict()
                if key not in pattern_dict[domain]:
                    pattern_dict[domain][key] = []
                pattern_dict[domain][key].extend(new_pattern_list)

    with open(dataset_path + "uri_pattern.json", "w") as f:
        f.write(json.dumps(pattern_dict, indent=4))

    return pattern_dict


def modify_csv_by_pattern(csv_path, pattern_dict):
    """

    """
    flag = False
    with open(csv_path, "r") as f_handle:
        reader = csv.reader(f_handle)
        line_copy = list(reader).copy()
        header = line_copy[0]
        domain_index = list(header).index("domain")
        uri_index = list(header).index("request_uri")
        for line in line_copy[1:]:
            if line[domain_index] in pattern_dict:
                if line[uri_index] and get_key_from_uri(line[uri_index]) in pattern_dict[line[domain_index]]:
                    # for pattern_str in pattern[line[domain_index]][get_key_from_uri(line[uri_index])]:
                    #     prefix = pattern_str.split("Abs_Len")[0]
                    #     suffix = "/".join(pattern_str.split("Ab_len_")[-1].split("/")[1:])
                    #     if prefix in line[uri_index] and suffix in line[uri_index]:
                    #         line[uri_index] = pattern_str
                    #         flag = True
                    #         break
                    pattern_oir_list_mode = format_tools.pattern_matching(line[uri_index], pattern_dict[line[domain_index]][get_key_from_uri(line[uri_index])])
                    if pattern_oir_list_mode:
                        line[uri_index] = "".join(pattern_oir_list_mode)
                        flag = True
    if flag:
        with open(csv_path, "w") as f_handle:
            writer = csv.writer(f_handle)
            writer.writerows(line_copy)


def modify_dataset_by_pattern(dataset, pattern):
    dataset_path = PACKET_ROOT_PATH + dataset + "/"
    operation_folders = os.listdir(dataset_path)

    for op in operation_folders:
        if not os.path.isdir(dataset_path + op):
            continue
        op_folder_path = dataset_path + op + "/"
        file_list = os.listdir(op_folder_path)

        # read from csv files
        for file in file_list:
            if op not in file or file.split(".")[-1] != "csv":
                continue
            modify_csv_by_pattern(op_folder_path + file, pattern)


def pre_parse(dataset_list: list):
    """
    Analyse dataset and learn how to extract an abstract response for LearnLib.
    :param dataset_list:
    """
    mlog.log_func(mlog.LOG, "Start pre-parsing...")
    mlog.log_func(mlog.LOG, "Dataset:  ")
    mlog.log_list_func(mlog.LOG, dataset_list)

    with open(ROOT_PATH + "/../config/black_list.json", "r") as bf:
        blackname_dict = json.load(bf)

    mlog.log_func(mlog.LOG, "Blacklist: ")
    mlog.log_dict_func(mlog.LOG, blackname_dict)

    temp_count = 0
    for dataset in dataset_list:
        mlog.log_func(mlog.LOG, f"Current dataset: {dataset}")

        """
        ================================ module 1 ================================
        Read pcapng files and extract header features.
        Save features in corresponding csv file.
        """
        mlog.log_func(mlog.LOG, "Start module 1: reading pcapng files and extracting features")

        dataset_path = PACKET_ROOT_PATH + dataset + "/"

        all_packet_folder_list = os.listdir(dataset_path)
        for operation_folder in all_packet_folder_list:
            if not os.path.isdir(dataset_path + operation_folder):
                continue

            mlog.log_func(mlog.LOG, f"-Operation: {operation_folder}")
            # get operation folder
            abs_operation_folder = dataset_path + operation_folder + "/"
            file_list = os.listdir(abs_operation_folder)
            # for each pcapng file, get its feature.csv file
            for item in file_list:
                if item.split('.')[-1] == "txt" and operation_folder in item:
                    temp_count += 1
                    mlog.log_func(mlog.LOG, str(temp_count) + " Reading file: " + item, t_count=1)
                    with open(abs_operation_folder + item, "r") as f:
                        lines = f.readlines()
                        pcap_name = lines[0].replace("\n", "")
                        start_time = lines[1].replace("\n", "")
                        end_time = lines[2].replace("\n", "")

                    # get the knowledge of dns mapping from ip to domain
                    dns_mapping_list = parse_dns_and_get_ip_domain(dataset + ".pcapng")

                    # read pcap file and extract features
                    keylog_file = pcap_name.split('.')[0] + ".txt"
                    cur_wireshark_filter_expression = format_tools.get_wireshark_filter_by_timestamp(start_time, end_time) + " and " + FILTER_CONDITION + " and " + format_tools.get_wireshark_filter_expression_by_blackname_list_dict(blackname_dict)
                    pcap = pyshark.FileCapture(dataset_path + pcap_name, display_filter=cur_wireshark_filter_expression,
                                               override_prefs={'ssl.keylog_file': dataset_path + keylog_file})
                    get_header_features(pcap, pcap_name, dns_mapping_list, save_csv_flag=True, op_file_name=item)
                    pcap.close()

                    while(len(lines) > 3):
                        lines.pop(-1)
                    lines.append("\n" + cur_wireshark_filter_expression)
                    with open(abs_operation_folder + item, "w") as f:
                        f.writelines(lines)

        # read dataset and get pattern
        pattern = get_url_pattern(dataset)
        modify_dataset_by_pattern(dataset, pattern)

        """
            ================================ module 2 ================================
            Filter packets which appear more than threshold times among all operations.
        """
        mlog.log_func(mlog.LOG, "Start module 2: filtering packet which appears more than threshold times among all operations.")

        feature_filter_by_general_list = []

        # Collect statistics on features whose number of occurrences exceeds the threshold
        black_dict = dict()
        with open(ROOT_PATH + "/../config/black_list.json", "r") as bf:
            black_dict = json.load(bf)
            # black_uri_list = black_dict["request_uri"]

        feature_filter_by_general_list.extend(black_dict["full_feature"])

        feature_ops_dict = {}
        count_of_op = 0
        # get feature aggregation from each csv and static appearance time
        for operation in os.listdir(dataset_path):
            # get operation folder
            abs_operation_folder = dataset_path + operation + "/"
            if not os.path.isdir(abs_operation_folder):
                continue
            count_of_op += 1
            file_list = os.listdir(abs_operation_folder)
            for cur_file in file_list:
                # find csv file
                if cur_file[-3:] != "csv":
                    continue

                # read csv file
                with open(abs_operation_folder + cur_file, "r") as file:
                    reader = csv.reader(file)
                    header = next(reader)
                    start_index = header.index("domain")
                    protocol_index = header.index("protocol")
                    lines = list(reader)
                    for line in lines:
                        cur_line_feature = "|".join(line[start_index:])

                        # filterd by black list
                        for black_key in black_dict.keys():
                            if black_key == "ip" or black_key == "full_feature":
                                continue
                            key_index = header.index(black_key)
                            if line[key_index] in black_dict[
                                black_key] and cur_line_feature not in feature_filter_by_general_list:
                                feature_filter_by_general_list.append(cur_line_feature)

                        if line[protocol_index] in protocol_to_be_filtered:
                            if cur_line_feature not in feature_ops_dict:
                                feature_ops_dict[cur_line_feature] = [operation]
                            elif operation not in feature_ops_dict[cur_line_feature]:
                                feature_ops_dict[cur_line_feature].append(operation)

        # sort by key
        feature_ops_dict = format_tools.sort_dict_by_key(feature_ops_dict)
        with open(dataset_path + "feature_static.json", "w") as f:
            f.write(json.dumps(feature_ops_dict, indent=4))

        # record feature in black list
        with open(dataset_path + "filtered_features.txt", "w") as f:
            for feature in feature_filter_by_general_list:
                f.write(feature)
                f.write("\n")

        # record feature by al
        with open(dataset_path + "filtered_features.txt", "a+") as f:
            for feature in feature_ops_dict:
                if feature not in feature_filter_by_general_list and len(
                        feature_ops_dict[feature]) >= threshold_among_each_kind_of_operation * count_of_op:
                    f.write(feature)
                    f.write("\n")
                    feature_filter_by_general_list.append(feature)

        """
            ================================ module 3 ================================
            Select the operation that occurs more than threshold(half) in one operation
        """
        mlog.log_func(mlog.LOG, "Start module 3: selecting the operation that occurs more than the threshold in one operation.")

        op_selected_features_dict = {}
        features_occur_for_each_time_dict = {}  # It is used to count the pattern corresponding to each feature when each click is executed under each operation
        # construct: {operation: {click_item: {feature: [payload_list]}}}

        for operation in os.listdir(dataset_path):
            total_op_pcap = 0
            fea_times_in_cur_op_dict = {}
            op_selected_features_dict[operation] = []

            op_folder = dataset_path + operation + "/"
            if not os.path.isdir(op_folder):
                continue

            if operation not in features_occur_for_each_time_dict:
                features_occur_for_each_time_dict[operation] = dict()

            for item in os.listdir(op_folder):
                if item.split(".")[-1] != "csv":
                    continue
                if item.split(".")[0] not in features_occur_for_each_time_dict[operation]:
                    features_occur_for_each_time_dict[operation][item.split(".")[0]] = {}
                total_op_pcap += 1
                # read csv file and get appear time for each feature
                with open(op_folder + item, "r") as file:
                    reader = csv.reader(file)
                    header = next(reader)
                    start_index = header.index("domain")
                    protocol_index = header.index("protocol")
                    lines = list(reader)
                    for line in lines:
                        cur_line_feature = "|".join(line[start_index:])
                        if line[protocol_index] not in protocol_to_be_filtered:
                            if cur_line_feature not in features_occur_for_each_time_dict[operation][item.split(".")[0]]:
                                features_occur_for_each_time_dict[operation][item.split(".")[0]][cur_line_feature] = []
                            continue
                        if cur_line_feature not in feature_filter_by_general_list:
                            if cur_line_feature not in fea_times_in_cur_op_dict:
                                fea_times_in_cur_op_dict[cur_line_feature] = []
                            if item not in fea_times_in_cur_op_dict[cur_line_feature]:
                                fea_times_in_cur_op_dict[cur_line_feature].append(item)
                            # add to features_occur_for_each_time_dict
                            if cur_line_feature not in features_occur_for_each_time_dict[operation][item.split(".")[0]]:
                                features_occur_for_each_time_dict[operation][item.split(".")[0]][cur_line_feature] = []

            with open(op_folder + "feature_static.json", "w") as f:
                f.write(json.dumps(fea_times_in_cur_op_dict, indent=4))

            with open(op_folder + "filtered_features.txt", "w") as f:
                for feature in fea_times_in_cur_op_dict:
                    if len(fea_times_in_cur_op_dict[feature]) < threshold_in_one_op * total_op_pcap:
                        f.write(feature)
                        f.write("\n")

            with open(op_folder + "selected_features.txt", "w") as f:
                for feature in fea_times_in_cur_op_dict:
                    if len(fea_times_in_cur_op_dict[feature]) >= threshold_in_one_op * total_op_pcap:
                        f.write(feature)
                        f.write("\n")
                        op_selected_features_dict[operation].append(feature)

        """
                    ================================ module 4 ================================
                    get payload and payload pattern
        """
        mlog.log_func(mlog.LOG, "Strat module 4: get payload from dataset")

        op_feature_pattern_dict = {}
        for operation in os.listdir(dataset_path):
            op_folder = dataset_path + operation + "/"
            if not os.path.isdir(op_folder):
                continue

            mlog.log_func(mlog.LOG, f"Current operation: {operation}", t_count=1)

            feature_payloads_dict = {}
            for op_files in os.listdir(op_folder):
                if op_files.split(".")[-1] != "csv":
                    continue

                # get pcap name, filter condition from txt
                txt_file_name = op_files.split(".")[0] + ".txt"
                with open(op_folder + txt_file_name, "r") as f:
                    txt_line = f.readlines()
                    filter_condition = txt_line[-1].replace("\n", "")
                    pcap_file_name = txt_line[0].replace("\n", "")
                    key_file_name = pcap_file_name.split(".")[0] + ".txt"

                # get selected packet number
                cur_op_selected_features = op_selected_features_dict[operation]
                selected_numbers_feature = {}
                with open(op_folder + op_files, "r") as f:
                    reader = csv.reader(f)
                    header = next(reader)
                    start_index = header.index("domain")
                    protocol_index = header.index("protocol")
                    resp_number_index = header.index("response_number")
                    req_number_index = header.index("number")
                    lines = list(reader)
                    for line in lines:
                        cur_line_feature = "|".join(line[start_index:])
                        if line[protocol_index] not in protocol_to_be_filtered:
                            selected_numbers_feature[line[req_number_index]] = cur_line_feature
                            continue
                        if cur_line_feature in cur_op_selected_features:
                            if line[resp_number_index]:
                                selected_numbers_feature[line[resp_number_index]] = cur_line_feature
                            else:
                                if line[protocol_index] != "http":
                                    selected_numbers_feature[line[req_number_index]] = cur_line_feature

                # read pcap file and get payload
                pcap = pyshark.FileCapture(dataset_path + pcap_file_name, display_filter=filter_condition, use_json=True,
                                           override_prefs={'ssl.keylog_file': dataset_path + key_file_name})
                for packet in pcap:
                    str_number = str(packet.number)
                    if str_number in selected_numbers_feature:
                        if selected_numbers_feature[str_number] not in feature_payloads_dict:
                            feature_payloads_dict[selected_numbers_feature[str_number]] = []
                        payload = get_payload_from_packet(packet)
                        feature_payloads_dict[selected_numbers_feature[str_number]].append(payload)
                        features_occur_for_each_time_dict[operation][op_files.split(".")[0]][selected_numbers_feature[str_number]].append(payload)
                pcap.close()

            # get patterns for payload split by length
            feature_payloads_pattern = {}
            for key in feature_payloads_dict:
                feature_payloads_dict[key] = split_list_by_length(feature_payloads_dict[key])
                if key not in feature_payloads_pattern:
                    feature_payloads_pattern[key] = []
                if "udp" not in key:
                    for len_split_payloads in feature_payloads_dict[key]:
                        feature_payloads_pattern[key].append(format_tools.get_patterns_for_cases(len_split_payloads))
                else:
                    for len_split_payloads in feature_payloads_dict[key]:
                        feature_payloads_pattern[key].append(format_tools.get_udp_payload_pattern(len_split_payloads))

            op_feature_pattern_dict[operation] = feature_payloads_pattern

            with open(dataset_path + operation + "/payload_static.json", "w") as f:
                f.write(json.dumps(feature_payloads_dict, indent=4))

            # get payload pattern
            with open(dataset_path + operation + "/payload_pattern.json", "w") as f:
                f.write(json.dumps(feature_payloads_pattern, indent=4))

        """
        ================================ module 5 ================================
            get abstract class for each class of pattern
        """
        mlog.log_func(mlog.LOG, "Strat module 5: classifying.")

        not_in_feature_list = []
        for operation in features_occur_for_each_time_dict.keys():
            for click_item in features_occur_for_each_time_dict[operation]:
                for feature in features_occur_for_each_time_dict[operation][click_item]:
                    # check if pattern for current feature is match
                    for index in range(len(features_occur_for_each_time_dict[operation][click_item][feature])):
                        if feature not in op_feature_pattern_dict[operation]:
                            not_in_feature_list.append((operation, click_item, feature))
                            continue
                        for each_len_patterns_list in op_feature_pattern_dict[operation][feature]:
                            matched_pattern = format_tools.pattern_matching(features_occur_for_each_time_dict[operation][click_item][feature][index], each_len_patterns_list, "udp" in feature)
                            if matched_pattern:
                                features_occur_for_each_time_dict[operation][click_item][feature][index] = "".join(matched_pattern)
                                break

                    features_occur_for_each_time_dict[operation][click_item][feature] = list(set(features_occur_for_each_time_dict[operation][click_item][feature]))

        # get class
        classify_dict = {}
        for operation in features_occur_for_each_time_dict.keys():
            if operation not in classify_dict:
                classify_dict[operation] = []
            for click_item in features_occur_for_each_time_dict[operation]:
                temp_list = []
                # Concatenate feature and pattern into a long string split by FPSPER
                for feature in features_occur_for_each_time_dict[operation][click_item]:
                    for pattern_str in features_occur_for_each_time_dict[operation][click_item][feature]:
                        fp_str = feature + "FPSPER" + pattern_str
                        temp_list.append(fp_str)
                temp_list = sorted(list(set(temp_list)))
                classify_dict[operation].append("CLSSPER".join(temp_list))

            classify_dict[operation] = list(set(classify_dict[operation]))
            # rename for class
            for i in range(len(classify_dict[operation])):
                classify_dict[operation][i] = classify_dict[operation][i].split("CLSSPER")

            with open(dataset_path + operation + "/classify_result.json", "w") as f:
                f.write(json.dumps(classify_dict[operation], indent=4))


def get_new_op_class_for_response(database, new_pcapng_file_name, keylog_file_path, op_name, start_time, end_time):
    """
    Giving a new pcapng file of an operation, get it's abstract class
    :param new_pcapng_file_name: pcapng_file under classifying, such as "SA_111.pcapng"
    :param keylog_file_path: PATH to decrypted file corresponding to the pcapng file
    :param op_name: current operation name
    :param start_time: start timestamp of op_name
    :param end_time: end timestamp of op_name
    :return: abstract class for response -> str
    """
    mlog.log_func(mlog.LOG, "Parse and get new response...")
    pcapng_root_path = PACKET_ROOT_PATH + new_pcapng_file_name.split(".")[0] + "/"
    pcapng_file_path = pcapng_root_path + new_pcapng_file_name

    if not os.path.exists(keylog_file_path):
        mlog.log_func(mlog.ERROR, "keylog file path error")
        return None

    # Concatenate the path of the database
    database_root_path = PACKET_ROOT_PATH + database + "/"

    # read filtered features from database
    filtered_features_list = []
    # get common filtered features
    with open(database_root_path + "filtered_features.txt", "r") as f:
        for line in f.readlines():
            if line:
                filtered_features_list.append(line.replace("\n", ""))

    # read filtered features for current op_name
    op_root_path = database_root_path + op_name + '/'
    with open(op_root_path + "filtered_features.txt", "r") as f:
        for line in f.readlines():
            if line:
                filtered_features_list.append(line.replace("\n", ""))

    # get selected features from database(use payload pattern features)
    with open(op_root_path + "payload_pattern.json", "r") as f:
        selected_features_list = list(json.load(f).keys())
    # with open(op_root_path + "selected_features.txt", "r") as f:
    #     for line in f.readlines():
    #         if line:
    #             selected_features_list.append(line.replace("\n", ""))

    # Convert features to regular expressions
    # convert filtered_features to patterns
    for index in range(len(filtered_features_list)):
        filtered_features_list[index] = format_tools.split_feature_str_to_pattern_list(filtered_features_list[index])
    # convert selected_features
    for index in range(len(selected_features_list)):
        selected_features_list[index] = format_tools.split_feature_str_to_pattern_list(selected_features_list[index])

    # get the knowledge of dns mapping from ip to domain
    dns_mapping = parse_dns_and_get_ip_domain(new_pcapng_file_name)
    # get blackname list
    with open(ROOT_PATH + "/../config/black_list.json", "r") as bf:
        black_dict = json.load(bf)

    mlog.log_func(mlog.LOG, "Get black list from file...")
    # mlog.log_dict_func(mlog.LOG, black_dict)

    # generate filter expression of current operation
    new_op_filter_expression = format_tools.get_wireshark_filter_by_timestamp(start_time, end_time) + " and " + FILTER_CONDITION + " and " + format_tools.get_wireshark_filter_expression_by_blackname_list_dict(black_dict)

    # save filter expression in file
    with open(pcapng_root_path + op_name + "/" + op_name + "_" + str(int(start_time)) + ".txt", "w") as op_st_f:
        op_st_f.write(new_pcapng_file_name + "\n")
        op_st_f.write(str(start_time) + "\n")
        op_st_f.write(str(end_time) + "\n")
        op_st_f.write(new_op_filter_expression)

    # read pcapng file and get header features
    pcap = pyshark.FileCapture(pcapng_file_path, display_filter=new_op_filter_expression,
                               override_prefs={'ssl.keylog_file': keylog_file_path})
    new_op_header_features_dict_list = get_header_features(pcap, new_pcapng_file_name, dns_mapping, save_csv_flag=False)
    pcap.close()

    # sort dict unit by list
    sorted_header_feature_list = []
    new_feature_index_list = []
    number_to_be_read_list = []
    sorted_header_feature_dict = OrderedDict()
    start_index = fieldnames_of_csv.index("domain")
    for ori_dict_index in range(len(new_op_header_features_dict_list)):
        ori_dict = new_op_header_features_dict_list[ori_dict_index]

        # jump if in the black list
        jump_flag = False
        for black_key in black_dict:
            if black_key == "ip" or black_key == "full_feature":
                continue
            if ori_dict[black_key] in black_dict[black_key]:
                jump_flag = True
                break
        if jump_flag:
            continue

        for key in fieldnames_of_csv:
            if ori_dict.get(key):
                sorted_header_feature_dict[key] = ori_dict.get(key)
            else:
                sorted_header_feature_dict[key] = ""

        # check if this line is in filter_lines
        current_line_str = "|".join(list(sorted_header_feature_dict.values())[start_index:])
        if not format_tools.pattern_matching(current_line_str, filtered_features_list):
            # not in filtered feature list
            sorted_header_feature_list.append(sorted_header_feature_dict)
            if sorted_header_feature_dict["protocol"] != "http":
                # get packet number in pcapng file
                number_to_be_read_list.append(sorted_header_feature_dict["response_number"] if sorted_header_feature_dict["response_number"] else sorted_header_feature_dict["number"])
            else:
                if sorted_header_feature_dict["response_number"]:
                    number_to_be_read_list.append(sorted_header_feature_dict["response_number"])

            # if it appears first time(not appear at selected feature list), need to be record
            if not format_tools.pattern_matching(current_line_str, selected_features_list):
                # element: index of new feature in sorted header feature list-> dict
                new_feature_index_list.append(len(sorted_header_feature_list) - 1)

        sorted_header_feature_dict = OrderedDict()

    # read payload patterns from database
    payload_file_path = database_root_path + op_name + '/payload_pattern.json'
    with open(payload_file_path, "r") as payload_file:
        payload_pattern_dict = json.load(payload_file)
    payload_pattern_features = list(payload_pattern_dict.keys())  # split feature-> pattern
    for feature_index in range(len(payload_pattern_features)):
        payload_pattern_features[feature_index] = format_tools.split_feature_str_to_pattern_list(payload_pattern_features[feature_index])

    # get payloads of this new operation
    # read pcapng file and get payload
    packet_number_payload_dict = dict()
    pcap = pyshark.FileCapture(pcapng_file_path, display_filter=new_op_filter_expression, use_json=True,
                               override_prefs={'ssl.keylog_file': keylog_file_path})
    for packet in pcap:
        str_number = str(packet.number)
        if str_number in number_to_be_read_list:
            packet_number_payload_dict[str_number] = get_payload_from_packet(packet)
    pcap.close()

    # read classify result from database
    database_classify_file_path = database_root_path + op_name + '/classify_result.json'
    with open(database_classify_file_path, "r") as f:
        database_classify_result = json.load(f)

    """
    
    """
    if new_feature_index_list:
        mlog.log_func(mlog.DEBUG, "Clear new feature for test")
        new_feature_index_list.clear()

    # get classify result for new operation
    if not new_feature_index_list:
        # each feature has appeared
        mlog.log_func(mlog.LOG, "All features has appeared")

        # return the same class for DCU1 for test
        if specific_response_flag:
            if op_name in specific_response_op_name_list:
                return op_name + "_CLS_-1"

        temp_feature_payload_combine_list = []  # "featureFPSPERpayload" list
        not_match_index_list = []  # feature is in database, but does not have match pattern, index for sorted_header_feature_list

        # use patterns to match payload
        for item_index in range(len(sorted_header_feature_list)):
            item = sorted_header_feature_list[item_index]

            if item["protocol"] == "http" and not item["response_number"]:
                continue

            current_line_str = "|".join(list(item.values())[start_index:])
            # get the corresponding pattern of this line str
            line_pattern = payload_pattern_features[format_tools.get_pattern_index_in_pattern_list(format_tools.pattern_matching(current_line_str, payload_pattern_features), payload_pattern_features)]
            if line_pattern and line_pattern != -1:
                try:
                    current_line_str = "".join(line_pattern)
                except TypeError:
                    mlog.log_func(mlog.ERROR, f"TypeError, bad pattern: {line_pattern}, current line: {current_line_str}")
                    return None
            else:
                mlog.log_func(mlog.DEBUG, f"Not in database: {current_line_str}")
                continue

            """
            
            """
            if current_line_str not in payload_pattern_dict:
                mlog.log_func(mlog.DEBUG, f"Not in database: {current_line_str}")
                continue

            current_feature_patterns = payload_pattern_dict[current_line_str]

            match_flag = False
            # Reads the payload from the dictionary read earlier
            current_payload = packet_number_payload_dict[item["response_number"] if item["response_number"] and item["response_number"] in packet_number_payload_dict else item["number"]]
            # Match the pattern of each length
            for each_len_patterns in current_feature_patterns:
                matching_result = format_tools.pattern_matching(current_payload, each_len_patterns, "udp" in current_line_str)
                if matching_result:
                    current_payload = "".join(matching_result)
                    match_flag = True
                    break
            # record the payload which does not match
            if not match_flag:
                # not_match_index_list.append(item_index)
                not_match_index_list.append(len(temp_feature_payload_combine_list)-1)
            if current_line_str + "FPSPER" + current_payload not in temp_feature_payload_combine_list:
                temp_feature_payload_combine_list.append(current_line_str + "FPSPER" + current_payload)

        # set and sorted
        temp_feature_payload_combine_list_sorted = sorted(temp_feature_payload_combine_list)

        # Compare with what has already been classified
        temp_feature_payload_combine_cls = "CLSSPER".join(temp_feature_payload_combine_list_sorted)
        for result_index in range(len(database_classify_result)):
            if temp_feature_payload_combine_cls == "CLSSPER".join(database_classify_result[result_index]):
                # If the current category exists, return result
                return op_name + "_CLS_" + str(result_index)

        if not_match_index_list:
            mlog.log_func(mlog.LOG, "Some payload doesn't have match pattern")
        else:
            mlog.log_func(mlog.LOG, "All payload match, but not in recent classify result")

        # If the current category not exists
        not_match_dict = {}
        # add not match payload
        for not_match_payload_index in not_match_index_list:
            cur_feature = temp_feature_payload_combine_list[not_match_payload_index].split("FPSPER")[0]
            cur_payload = temp_feature_payload_combine_list[not_match_payload_index].split("FPSPER")[-1]

            if cur_feature not in not_match_dict:
                not_match_dict[cur_feature] = []
            not_match_dict[cur_feature].append(cur_payload)

        # read payload static from file
        with open(database_root_path + op_name + "/payload_static.json", "r") as static_file:
            payload_static_dict = json.load(static_file)

        # merge
        for cur_feature in not_match_dict:
            static_payload_list = payload_static_dict[cur_feature]
            total_payload_list = []

            # merge each length from database
            for each_len_payload in static_payload_list:
                total_payload_list.extend(each_len_payload)

            # merge new payload
            total_payload_list.extend(not_match_dict[cur_feature])

            # split by length
            payload_static_dict[cur_feature] = split_list_by_length(total_payload_list)

            # get pattern for merged payload
            payload_pattern_dict[cur_feature] = format_tools.get_patterns_for_feature_payload_list(payload_static_dict[cur_feature], "udp" in cur_feature)

        # add to payload static file
        with open(database_root_path + op_name + "/payload_static.json", "w") as static_file:
            static_file.write(json.dumps(payload_static_dict, indent=4))

        # add to payload pattern file
        with open(database_root_path + op_name + "/payload_pattern.json", "w") as payload_file:
            payload_file.write(json.dumps(payload_pattern_dict, indent=4))

        # get new classify result
        for not_match_payload_index in not_match_index_list:
            feature_fpsper_payload = temp_feature_payload_combine_list[not_match_payload_index]
            cur_feature = feature_fpsper_payload.split("FPSPER")[0]
            cur_payload = feature_fpsper_payload.split("FPSPER")[-1]

            # use new pattern to match
            for each_len_patterns in payload_pattern_dict[cur_feature]:
                matching_result = format_tools.pattern_matching(cur_payload, each_len_patterns, "udp" in cur_feature)
                if matching_result:
                    cur_payload = "".join(matching_result)
                    break

            temp_feature_payload_combine_list[not_match_payload_index] = cur_feature + "FPSPER" + cur_payload

        # set and sorted
        temp_feature_payload_combine_list = sorted(list(set(temp_feature_payload_combine_list)))

        # add to classify result
        database_classify_result.append(temp_feature_payload_combine_list)

        # write to file
        with open(database_classify_file_path, "w") as classify_file:
            classify_file.write(json.dumps(database_classify_result, indent=4))

        mlog.log_func(mlog.LOG, "New class!!")

        # return classify result
        return op_name + "_CLS_" + str(len(database_classify_result) - 1)

    else:
        # Some features have not been seen before
        mlog.log_func(mlog.LOG, "Find new features!!!")
        # get new feature dict and pattern
        new_feature_payload_dict = dict()
        mlog.log_func(mlog.LOG, "An emerging feature is being processed")
        for new_feature_index in new_feature_index_list:
            new_fea_item_dict = sorted_header_feature_list[new_feature_index]

            if new_fea_item_dict["protocol"] == "http" and not new_fea_item_dict["response_number"]:
                continue

            current_line_str = "|".join(list(new_fea_item_dict.values())[start_index:])
            mlog.log_func(mlog.LOG, "Current new feature: " + current_line_str)

            if new_fea_item_dict["response_number"]:
                current_payload = packet_number_payload_dict[new_fea_item_dict["response_number"]]
            else:
                if new_fea_item_dict["protocol"] != "http":
                    current_payload = new_fea_item_dict["number"]

            if current_line_str not in new_feature_payload_dict:
                new_feature_payload_dict[current_line_str] = []
            if current_payload not in new_feature_payload_dict[current_line_str]:
                new_feature_payload_dict[current_line_str].append(current_payload)

        # split by length
        for current_feature in new_feature_payload_dict:
            new_feature_payload_dict[current_feature] = split_list_by_length(new_feature_payload_dict[current_feature])

        # add to static file
        with open(database_root_path + op_name + "/payload_static.json", "r") as static_file:
            payload_static_dict = json.load(static_file)
        for new_feature in new_feature_payload_dict:
            payload_static_dict[new_feature] = new_feature_payload_dict[new_feature]
        with open(database_root_path + op_name + "/payload_static.json", "w") as static_file:
            static_file.write(json.dumps(payload_static_dict, indent=4))

        # get pattern for new features
        for current_feature in new_feature_payload_dict:
            if "udp" not in current_feature:
                for each_len_list_index in range(len(new_feature_payload_dict[current_feature])):
                    new_feature_payload_dict[current_feature][each_len_list_index] = format_tools.get_patterns_for_cases(new_feature_payload_dict[current_feature][each_len_list_index])
            else:
                for each_len_list_index in range(len(new_feature_payload_dict[current_feature])):
                    new_feature_payload_dict[current_feature][each_len_list_index] = format_tools.get_udp_payload_pattern(new_feature_payload_dict[current_feature][each_len_list_index])

            # add new feature pattern to pattern dict
            payload_pattern_dict[current_feature] = new_feature_payload_dict[current_feature]

        # add to pattern file
        with open(database_root_path + op_name + "/payload_pattern.json", "w") as pattern_file:
            pattern_file.write(json.dumps(payload_pattern_dict, indent=4))

        payload_pattern_features = list(payload_pattern_dict.keys())  # split feature-> pattern
        for feature_index in range(len(payload_pattern_features)):
            payload_pattern_features[feature_index] = format_tools.split_feature_str_to_pattern_list(
                payload_pattern_features[feature_index])

        # add to select_features file
        selected_features_list = []
        with open(op_root_path + "selected_features.txt", "r") as f:
            for line in f.readlines():
                if line:
                    selected_features_list.append(line.replace("\n", ""))
        selected_features_list.extend(list(new_feature_payload_dict.keys()))
        with open(database_root_path + op_name + "/selected_features.txt", "w") as sele_fea_file:
            for feature_index in range(len(selected_features_list) - 1):
                sele_fea_file.write(selected_features_list[feature_index])
                sele_fea_file.write("\n")
            sele_fea_file.write(selected_features_list[-1])

        # get classify str
        temp_feature_payload_combine_list = []

        # use patterns to match payload
        for item_index in range(len(sorted_header_feature_list)):
            item = sorted_header_feature_list[item_index]

            if item["protocol"] == "http" and not item["response_number"]:
                continue

            current_line_str = "|".join(list(item.values())[start_index:])
            current_line_str = "".join(payload_pattern_features[format_tools.get_pattern_index_in_pattern_list(
                format_tools.pattern_matching(current_line_str, payload_pattern_features), payload_pattern_features)])
            if current_line_str in payload_pattern_dict:
                # get payload pattern for current feature
                current_feature_patterns = payload_pattern_dict[current_line_str]

                # Reads the payload from the dictionary read earlier
                current_payload = packet_number_payload_dict[
                    item["response_number"] if item["response_number"] in packet_number_payload_dict else item[
                        "number"]]
                for each_len_patterns in current_feature_patterns:
                    matching_result = format_tools.pattern_matching(current_payload, each_len_patterns, "udp" in current_line_str)
                    if matching_result:
                        current_payload = "".join(matching_result)
                        break
                temp_feature_payload_combine_list.append(current_line_str + "FPSPER" + current_payload)
            else:
                # There are still features that the previous code could not handle
                payload_pattern_dict[current_line_str] = []
                mlog.LOG(mlog.ERROR, "ERROR -1")
                exit(-1)

        # set and sorted
        temp_feature_payload_combine_list = sorted(list(set(temp_feature_payload_combine_list)))

        # add to classify result
        database_classify_result.append(temp_feature_payload_combine_list)
        # write to file
        with open(database_classify_file_path, "w") as classify_file:
            classify_file.write(json.dumps(database_classify_result, indent=4))

        mlog.log_func(mlog.LOG, "New class!!")

        # return classify result
        return op_name + "_CLS_" + str(len(database_classify_result)-1)


if __name__ == "__main__":
    mlog.clear_log()

    import time

    start_time = time.time()
    pre_parse(["manual_dataset_1709359674"])
    # print(get_new_op_class_for_response("manual_dataset_1709359674", "manual_dataset_1708781404.pcapng", PACKET_ROOT_PATH + 'manual_dataset_1708781404/manual_dataset_1708781404.txt', "DCU1", 1708781573.2821207, 1708781577.2241092))
    # print(get_new_op_class_for_response("manual_dataset_1709359674", "manual_dataset_1708781404.pcapng", PACKET_ROOT_PATH + 'manual_dataset_1708781404/manual_dataset_1708781404.txt', "ADU1CWR", 1708781483.8227053, 1708781533.441152))
    end_time = time.time()
    print("time: ", end_time - start_time)
    print("============================")

