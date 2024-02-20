import json
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction.text import CountVectorizer
import pyshark
import os
import csv
import numpy as np
import re
import Levenshtein
from collections import defaultdict
import xmltodict

import get_ips
import my_classify
import jsonlayer_parser, format_tools
from log import mlog
from protocol_feature import feature_dict

ROOT_PATH = os.path.dirname(__file__)
PACKET_ROOT_PATH = ROOT_PATH + "/packets/"

FILTER_CONDITION = "((http or mqtt or ((udp and !dns) and (udp and !mdns))) and !bootp and !(ip.addr == 10.42.0.1) and !(ip.addr == 238.238.238.238) and !coap)"
merged_ip_list = get_ips.merge_manual_ip_list([])
condition_sentence = get_ips.generate_filter_condition_by_ip_list(merged_ip_list)
FILTER_CONDITION = FILTER_CONDITION + " and " + condition_sentence

ABSTRACT_FEATURE = "HAS_FEATURE"

# similarity threshold of documents. if larger than similarity_threshold, regard as the same word
similarity_threshold = 0.9
threshold_multiplier = 1
threshold_among_each_kind_of_operation = 0.5
threshold_in_one_op = 0.9

"""can delete"""
test_flag = False
no_need_mapping_flag = False

pcapng_order_and_length_dict = {}
result_document_of_each_pcapng = {}
word_for_each_pcapng = {}

not_feature_list = feature_dict["record"]

disabled_words = ["HTTP response", "Group:", "Date:", "Request:", "Response:", " in frame:", "Time since request:",
                  "Prev ", "prev_", "HTTP request", "Severity level:", "Expert Info ", "Status Code Description:",
                  "request_number:", "request_in:", "response_number:"]
enhance_feature_dict = {
    "request_method": 10,
    "topic": 0,
    "request_uri": 0,
    "uri_word_counts": 8,
}

fieldnames_of_csv = []
for protocol_name in feature_dict.keys():
    fieldnames_of_csv.extend(feature_dict[protocol_name])


def get_final_important_words_for_each_op(op_list, important_words_selected_by_threshold):
    """

    """
    each_op_important_words = {}

    # get intersection important words of each op
    for op_name in op_list:
        abs_operation_folder = PACKET_ROOT_PATH + op_name + "/"
        csv_file_list = os.listdir(abs_operation_folder)
        csv_file_list = [x for x in csv_file_list if x.split(".")[-1] == "csv"]

        imp_word_for_each_pcap = []
        for cur_file in csv_file_list:
            imp_word_for_each_pcap.append([])
            # read csv file and mark important words in csv file
            corresponding_csv_file = abs_operation_folder + cur_file
            with open(corresponding_csv_file, "r") as f:
                reader = csv.reader(f)
                rows = list(reader)
            header = rows[0]
            mapping_word_index = header.index("mapping_word")
            for i in range(1, len(rows)):
                if rows[i][mapping_word_index] not in imp_word_for_each_pcap[-1] and rows[i][mapping_word_index] in important_words_selected_by_threshold:
                    imp_word_for_each_pcap[-1].append(rows[i][mapping_word_index])

        # get intersection
        word_intersection = set(imp_word_for_each_pcap[0])
        for subset in imp_word_for_each_pcap[1:]:
            word_intersection = word_intersection.intersection(subset)
        each_op_important_words[op_name] = list(word_intersection)

    # filter words which appear in half of op
    word_number_mapping = defaultdict(int)
    for key, value in each_op_important_words.items():
        for word in value:
            word_number_mapping[word] += 1
    word_intersection = [word for word, count in word_number_mapping.items() if count >= (len(each_op_important_words.keys()) / 2)]

    for key in each_op_important_words.keys():
        each_op_important_words[key] = list(set(each_op_important_words[key]).difference(set(word_intersection)))

    return each_op_important_words


# def get_important_packet_line_dict_by_important_word_for_cur_pcapng(op_name, final_important_word_list, new_pcap_file_name=None):
#     file_list = os.listdir(PACKET_ROOT_PATH + op_name + "/")
#     if not new_pcap_file_name:
#         pcapng_file_list = [f for f in file_list if "pcapng" in f]
#     else:
#         with open(PACKET_ROOT_PATH + op_name + "/classify_result.json", "r") as f:
#             classify_result = json.load(f)
#         pcapng_file_list = list(classify_result.keys())
#         pcapng_file_list.append(new_pcap_file_name)
#
#     # return result
#     remove_list = []
#
#     # initialize
#     pcap_word_lines_dict = {}
#     for pcapng_name in pcapng_file_list:
#         pcapng_name = pcapng_name.split(".")[0]
#         pcap_word_lines_dict[pcapng_name] = {}
#         cur_csv_path = PACKET_ROOT_PATH + op_name + '/' + pcapng_name + ".csv"
#
#         # read csv file
#         with open(cur_csv_path, "r") as f:
#             reader = csv.reader(f)
#             rows = list(reader)
#         # rows[0].append("final_select")
#         mapping_word_index = rows[0].index("mapping_word")
#
#         # get each word_line, if the same line appear more than once, use the latest line cover the old
#         # So we regard the line string as key, line number as the value
#         for row in rows[1:]:
#             if mapping_word_index >= len(row):
#                 continue
#             if row[mapping_word_index] in final_important_word_list:
#                 if row[mapping_word_index] not in pcap_word_lines_dict[pcapng_name].keys():
#                     pcap_word_lines_dict[pcapng_name][row[mapping_word_index]] = {}
#                 # if the word has appeared, save the latest one
#                 pcap_word_lines_dict[pcapng_name][row[mapping_word_index]][",".join(row[common_field_count:mapping_word_index])] = rows.index(row)
#
#     for word in final_important_word_list:
#         line_count_dict = defaultdict(int)
#         for pcapng_name in pcap_word_lines_dict.keys():
#             for line in pcap_word_lines_dict[pcapng_name][word].keys():
#                 line_count_dict[line] += 1
#         # select
#         if len(line_count_dict.keys()) > 1:
#             # when more than one packet was mapped to the same word, select the most one
#             line_count_dict = dict(sorted(line_count_dict.items(), key=lambda x: x[1], reverse=True))
#             keep_line = list(line_count_dict.keys())[0]
#             for pcapng_name in pcap_word_lines_dict.keys():
#                 if keep_line in pcap_word_lines_dict[pcapng_name][word].keys():
#                     keep_line_number = pcap_word_lines_dict[pcapng_name][word][keep_line]
#                     pcap_word_lines_dict[pcapng_name][word] = {}
#                     pcap_word_lines_dict[pcapng_name][word][keep_line] = keep_line_number
#                 else:
#                     remove_list.append(pcapng_name)
#
#     # remove other line
#     for pcapng_name in set(remove_list):
#         del pcap_word_lines_dict[pcapng_name]
#
#     for pcapng_name in pcap_word_lines_dict.keys():
#         for word in pcap_word_lines_dict[pcapng_name].keys():
#             line = list(pcap_word_lines_dict[pcapng_name][word].keys())[0]
#             pcap_word_lines_dict[pcapng_name][word] = pcap_word_lines_dict[pcapng_name][word][line]
#     return pcap_word_lines_dict


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


def get_header_features_from_csv_files_and_enhance(csv_files, feature_columns, enhance_feature_columns):
    """

    """
    features = []
    for file in csv_files:
        if file[-3:] != "csv":
            # get true file path
            file = PACKET_ROOT_PATH + file.split('_')[0] + '/' + file + ".csv"
        else:
            file = PACKET_ROOT_PATH + file.split('_')[0] + '/' + file

        # get features
        with open(file, 'r') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                feature = ' '.join([row[col] for col in feature_columns])

                # enhance
                for en_col in enhance_feature_columns.keys():
                    en_count = enhance_feature_columns[en_col]
                    if en_count != 0:
                        for i in range(en_count):
                            feature += (' ' + row[en_col])
                    else:
                        # for uri, we think the prior field is more important
                        for uri_word_index in range(len(row[en_col].split())):
                            cur_uri_word = row[en_col].split()[uri_word_index]
                            for i in range(3):
                                feature += (' uw_' + str(uri_word_index) + '_len_' + str(len(cur_uri_word)))
                            for uri_word_enhance_count in range((len(row[en_col].split()) - uri_word_index)):
                                feature += (' ' + cur_uri_word)
                        for i in range(len(row[en_col].split())):
                            feature += (' ' + cur_uri_word)
                features.append(feature)

    return features


def get_important_features_and_enhanced(csv_files, feature_columns, enhance_feature_columns):
    """

    """
    features = []
    words = []
    for file in csv_files:
        if file[-3:] != "csv":
            # get true file path
            file = PACKET_ROOT_PATH + file.split('_')[0] + '/' + file + ".csv"
        else:
            file = PACKET_ROOT_PATH + file.split('_')[0] + '/' + file

        # get features
        with open(file, 'r') as csv_file:
            reader = csv.reader(csv_file)
            rows = list(reader)
        final_select_index = rows[0].index("final_select")
        mapping_word_index = rows[0].index("mapping_word")
        for row in rows[1:]:
            # whether it is important
            if final_select_index >= len(row) or row[final_select_index] != "222":
                continue
            words.append(row[mapping_word_index])
            feature = ' '.join([row[rows[0].index(col)] for col in feature_columns])

            # enhance
            for en_col in enhance_feature_columns.keys():
                en_count = enhance_feature_columns[en_col]
                en_col_index = rows[0].index(en_col)
                if en_count != 0:
                    for i in range(en_count):
                        feature += (' ' + row[en_col_index])
                else:
                    # for uri, we think prior is more important
                    for uri_word_index in range(len(row[en_col_index].split())):
                        cur_uri_word = row[en_col_index].split()[uri_word_index]
                        for i in range(3):
                            feature += (' uw_' + str(uri_word_index) + '_len_' + str(len(cur_uri_word)))
                        for uri_word_enhance_count in range((len(row[en_col_index].split()) - uri_word_index)):
                            feature += (' ' + cur_uri_word)
                    for i in range(len(row[en_col_index].split())):
                        feature += (' ' + cur_uri_word)
            features.append(feature)

    return features, words


def vectorize_features(features):
    vectorizer = CountVectorizer()
    feature_vectors = vectorizer.fit_transform(features)
    return feature_vectors


def get_phone_ips():
    from config.device_appium_config import device_configs
    ips = []
    for phone, conf in device_configs.items():
        ip = conf["additionalMess"]["phone_ip"]
        if ip not in ips:
            ips.append(ip)
    return ips


def get_header_features(pcap, save_folder, pcapng_file_name, dns_mapping_list):
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
                            merge_flag = True
                            break

            else:
                for field_name in feature_dict[protocol_name]:
                    packet_feature_dict[field_name] = None

        if not merge_flag:
            pcap_feature_dict_list.append(packet_feature_dict)
            packet_num += 1

        merge_flag = False

    # save csv file
    csv_name = save_folder + pcapng_file_name.split(".")[0] + ".csv"
    with open(csv_name, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames_of_csv)
        writer.writeheader()
        writer.writerows(pcap_feature_dict_list)


def get_dataset_csv_list(op_name):
    op_folder = PACKET_ROOT_PATH + op_name + "/"
    classify_file = op_folder + "classify_result.json"

    dataset_list = []
    with open(classify_file, "r") as f:
        temp_file = json.load(f)
        temp_dict = {}
        for key, value in temp_file.items():
            if value not in temp_dict:
                temp_dict[value] = key
                dataset_list.append(key)
        # dataset_list = list(temp_file.keys())

    # add ".csv" to the end
    dataset_list = [(x + '.csv') for x in dataset_list]

    return dataset_list


def get_header_features_from_dataset(op_name):
    """

    """
    # get dataset csv file list
    file_list = get_dataset_csv_list(op_name)

    # remove some fields
    temp_fieldnames_of_csv = []
    for n_fea in fieldnames_of_csv:
        if n_fea not in not_feature_list:
            temp_fieldnames_of_csv.append(n_fea)

    features, cor_words = get_important_features_and_enhanced(file_list, temp_fieldnames_of_csv, enhance_feature_dict)

    return features, cor_words


def get_important_words_from_dataset(op_name):
    # get important words from important_words.txt
    with open(PACKET_ROOT_PATH + op_name + "/important_words.txt", "r") as imp_word_file:
        imp_line = imp_word_file.readlines()[0].replace("\n", "")
    imp_words_list = imp_line.split(" | ")
    return imp_words_list


def get_payload_from_packet(packet):
    highest_layer_name = get_highest_except_segments_layer_name(packet)
    return_str = None

    # udp
    if "udp" in packet:
        if highest_layer_name == "data":
            if packet.data.data.isascii():
                ascii_str_list = str(packet.data.data).split(":")

                return_str = ""
                for ascii_value in ascii_str_list:
                    try:
                        char = chr(int(ascii_value, 16))
                        return_str += char
                    except ValueError:
                        mlog.log_func(mlog.ERROR, "Invalid ASCII value:" + ascii_value)
                        exit(2)
            else:
                return_str = str(packet.data.data)

    # tcp
    if "tcp" in packet:
        # http
        if "http" in packet:
            # with file_data
            if "file_data" in packet.http.field_names:
                return_str = packet.http.file_data
            else:
                # just with return code
                return_str = sorted(packet.http.field_names)[0]
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
                # return str(mqtt_info)

    if return_str:
        return str(return_str)
    else:
        return "payload_is_None"


def get_payload_from_preprogress_dataset(op_name):
    """

    """
    return_result = {}

    # get csv files
    op_folder = PACKET_ROOT_PATH + op_name + "/"
    file_list = get_dataset_csv_list(op_name)

    for csv_file in file_list:
        return_result[csv_file.split(".")[0]] = {}
        csv_file_path = op_folder + csv_file
        with open(csv_file_path, "r") as file:
            reader = csv.reader(file)
            rows = list(reader)
        header = rows[0]
        mapping_word_index = header.index("mapping_word")
        for row in rows:
            if row[-2] == "222":
                if row[-4] not in return_result[csv_file.split(".")[0]].keys():
                    return_result[csv_file.split(".")[0]][row[mapping_word_index]] = [[rows.index(row), row[0], row[1]], [row[-1]]]
                else:
                    return_result[csv_file.split(".")[0]][row[mapping_word_index]].append([rows.index(row), row[0], row[1]])
                    return_result[csv_file.split(".")[0]][row[mapping_word_index]].append([row[-1]])

    return return_result


def calculate_entropy(strings):
    total_edit_distance = 0
    num_pairs = 0

    for i in range(len(strings)):
        for j in range(i + 1, len(strings)):
            edit_distance = Levenshtein.distance(strings[i], strings[j])
            total_edit_distance += edit_distance
            num_pairs += 1

    if num_pairs == 0:
        return 0

    entropy = total_edit_distance / num_pairs
    return entropy


def split_list_by_length(strings):
    length_dict = defaultdict(list)

    for temp_index in range(len(strings)):
        if strings[temp_index]:
            length = len(strings[temp_index])
            length_dict[length].append(strings[temp_index])
        else:
            length_dict['0'].append(strings[temp_index])

    result = list(length_dict.values())
    return result


def filter_significant_and_zero_values(numbers, threshold):
    significant_values = []
    zero_values = []

    for i, num in enumerate(numbers):
        if num > threshold:
            significant_values.append((num, i))
        elif num == 0:
            zero_values.append(i)

    return significant_values, zero_values


def format_payload_str_by_entropy_and_pattern(word_number_dict, important_word_list, entropy_threshold, get_new_resp_flag=False):
    # use abstract str to exchange field which has high entropy and pattern
    for cur_word in important_word_list:
        ori_layer_strings_of_cur_word_list = []
        for pcapng_name in word_number_dict.keys():
            if cur_word in word_number_dict[pcapng_name].keys():
                for layer_index in range(1, len(word_number_dict[pcapng_name][cur_word]), 2):
                    if "||" in word_number_dict[pcapng_name][cur_word][layer_index][0]:
                        ori_layer_strings_of_cur_word_list.append([pcapng_name, cur_word, layer_index, (word_number_dict[pcapng_name][cur_word][layer_index][0]).split("||")])
                    else:
                        ori_layer_strings_of_cur_word_list.append([pcapng_name, cur_word, layer_index, (word_number_dict[pcapng_name][cur_word][layer_index][0]).split(",")])

        split_len_list = split_list_by_length([x[-1] for x in ori_layer_strings_of_cur_word_list])
        if not get_new_resp_flag:
            entropy_for_each_len_list = []
            cur_index_in_split_len_list = 0
            for each_len_str_list in split_len_list:
                index_list = [x[0] for x in each_len_str_list]
                each_len_str_list = [x[1] for x in each_len_str_list]
                entropy_for_each_len_list.append([])
                for temp_index in range(len(each_len_str_list[0])):
                    entropy_for_each_len_list[-1].append(
                        calculate_entropy(list(map(lambda lst: lst[temp_index], each_len_str_list))))
                sig_value_and_index, zero_values_index_list = filter_significant_and_zero_values(
                    entropy_for_each_len_list[-1], entropy_threshold)

                # use index to remove fields that have significant entropy
                for str_index in range(len(each_len_str_list)):
                    for value_index in sig_value_and_index:
                        index = value_index[1]
                        each_len_str_list[str_index][index] = "--sig_entropy--"
                    # each_len_str_list[str_index] = "||".join(each_len_str_list[str_index])

                # remove fields that change more than half
                change_index_list = format_tools.get_diff_index_in_list(each_len_str_list)
                for str_index in range(len(each_len_str_list)):
                    for i in change_index_list:
                        each_len_str_list[str_index][i] = "--change_most_time--"
                    each_len_str_list[str_index] = "||".join(each_len_str_list[str_index])
                split_len_list[cur_index_in_split_len_list] = [[index_list[i], each_len_str_list[i]] for i in range(len(each_len_str_list))]

                for i in range(len(each_len_str_list)):
                    ori_layer_strings_of_cur_word_list[index_list[i]][-1] = each_len_str_list[i]
                    pcapng_name_i = ori_layer_strings_of_cur_word_list[index_list[i]][0]
                    word_i = ori_layer_strings_of_cur_word_list[index_list[i]][1]
                    layer_index_i = ori_layer_strings_of_cur_word_list[index_list[i]][2]
                    word_number_dict[pcapng_name_i][word_i][layer_index_i] = each_len_str_list[i]

                cur_index_in_split_len_list += 1
        else:
            re_pattern = r'--.*--'
            cur_index_in_split_len_list = 0
            for each_len_str_list in split_len_list:
                index_list = [x[0] for x in each_len_str_list]
                each_len_str_list = [x[1] for x in each_len_str_list]
                old_str_list_model = each_len_str_list[0]
                for word_index in range(len(old_str_list_model)):
                    if re.search(re_pattern, old_str_list_model[word_index]):
                        each_len_str_list[-1][word_index] = old_str_list_model[word_index]
                for str_index in range(len(each_len_str_list)):
                    each_len_str_list[str_index] = "||".join(each_len_str_list[str_index])
                split_len_list[cur_index_in_split_len_list] = [[index_list[i], each_len_str_list[i]] for i in
                                                               range(len(each_len_str_list))]

                for i in range(len(each_len_str_list)):
                    ori_layer_strings_of_cur_word_list[index_list[i]][-1] = each_len_str_list[i]
                    pcapng_name_i = ori_layer_strings_of_cur_word_list[index_list[i]][0]
                    word_i = ori_layer_strings_of_cur_word_list[index_list[i]][1]
                    layer_index_i = ori_layer_strings_of_cur_word_list[index_list[i]][2]
                    word_number_dict[pcapng_name_i][word_i][layer_index_i] = each_len_str_list[i]

                cur_index_in_split_len_list += 1

    return word_number_dict


def get_dataset_name_list():
    return_list = []
    all_file_list = os.listdir(PACKET_ROOT_PATH)
    for item in all_file_list:
        if "_" in item and os.path.isdir(PACKET_ROOT_PATH + item):
            return_list.append(item)

    return return_list


def parse_dns_and_get_ip_domain(pcap_file):
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

    cap = pyshark.FileCapture(pcap_file, display_filter="dns")
    for packet in cap:
        if "dns" not in dir(packet):
            continue
        if 'resp_name' in packet.dns.field_names:
            dns_layer = packet.dns
            parse_result = parse_dns_response(dns_layer)
            if parse_result not in dns_mapping_list:
                dns_mapping_list.append(parse_result)
    cap.close()

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
            # len_threshold = len(uri_list) * threshold
            # split_list = [x.split("/") for x in uri_list]
            # for temp_index in range(len(split_list[0])):
            #     temp_list = list(set([uri[temp_index] for uri in split_list]))
            #     if len(temp_list) != 1 and len(temp_list) > len_threshold:
            #         for change_index in range(len(uri_list)):
            #             abstract_str = "Ab_Len" + str(len(temp_list[0]))
            #             sp = uri_list[change_index].split("/")
            #             sp[temp_index] = abstract_str
            #             uri_list[change_index] = "/".join(sp)
            #         # add to pattern dictionary
            #         if domain not in pattern_dict:
            #             pattern_dict[domain] = dict()
            #         if key not in pattern_dict[domain]:
            #             pattern_dict[domain][key] = []
            #         pattern_dict[domain][key].extend(list(set(uri_list)))
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
    mlog.log_func(mlog.LOG, "Dataset: ")
    mlog.log_list_func(mlog.LOG, dataset_list)

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

        # get the knowledge of dns mapping from ip to domain
        dns_mapping = parse_dns_and_get_ip_domain(dataset_path + dataset + ".pcapng")

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

                    # read pcap file and extract features
                    keylog_file = pcap_name.split('.')[0] + ".txt"
                    cur_wireshark_filter_expression = format_tools.get_wireshark_filter_by_timestamp(start_time, end_time) + " and " + FILTER_CONDITION
                    pcap = pyshark.FileCapture(dataset_path + pcap_name, display_filter=cur_wireshark_filter_expression,
                                                  override_prefs={'ssl.keylog_file': dataset_path + keylog_file})
                    get_header_features(pcap, abs_operation_folder, item, dns_mapping)
                    pcap.close()

                    if len(lines) <= 3:
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
                        if line[protocol_index] != "http":
                            continue
                        if cur_line_feature not in feature_ops_dict:
                            feature_ops_dict[cur_line_feature] = [operation]
                        elif operation not in feature_ops_dict[cur_line_feature]:
                            feature_ops_dict[cur_line_feature].append(operation)

        # sort by key
        feature_ops_dict = format_tools.sort_dict_by_key(feature_ops_dict)
        with open(dataset_path + "fea_ops.json", "w") as f:
            f.write(json.dumps(feature_ops_dict, indent=4))

        # Collects statistics on features whose number of occurrences exceeds the threshold
        feature_filter_by_general_list = []
        with open(dataset_path + "filtered_features.txt", "w") as f:
            for feature in feature_ops_dict:
                if len(feature_ops_dict[feature]) >= threshold_among_each_kind_of_operation * count_of_op:
                    f.write(feature)
                    f.write("\n")
                    feature_filter_by_general_list.append(feature)

        """
            ================================ module 3 ================================
            Select the operation that occurs more than the threshold in one operation
        """
        mlog.log_func(mlog.LOG, "Start module 3: selecting the operation that occurs more than the threshold in one operation.")

        op_selected_features_dict = {}

        for operation in os.listdir(dataset_path):
            total_op_pcap = 0
            fea_times_in_cur_op_dict = {}
            op_selected_features_dict[operation] = []

            op_folder = dataset_path + operation + "/"
            if not os.path.isdir(op_folder):
                continue

            for item in os.listdir(op_folder):
                if item.split(".")[-1] != "csv":
                    continue
                total_op_pcap += 1
                # read csv file and get appear time for each feature
                with open(op_folder + item, "r") as file:
                    reader = csv.reader(file)
                    header = next(reader)
                    start_index = header.index("domain")
                    protocol_index = header.index("protocol")
                    lines = list(reader)
                    for line in lines:
                        if line[protocol_index] != "http":
                            continue
                        cur_line_feature = "|".join(line[start_index:])
                        if cur_line_feature not in feature_filter_by_general_list:
                            if cur_line_feature not in fea_times_in_cur_op_dict:
                                fea_times_in_cur_op_dict[cur_line_feature] = []
                            if item not in fea_times_in_cur_op_dict[cur_line_feature]:
                                fea_times_in_cur_op_dict[cur_line_feature].append(item)

            with open(op_folder + "static_times.json", "w") as f:
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
        for operation in os.listdir(dataset_path):
            op_folder = dataset_path + operation + "/"
            if not os.path.isdir(op_folder):
                continue

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
                        if line[protocol_index] != "http":
                            selected_numbers_feature[line[req_number_index]] = cur_line_feature
                            continue
                        if cur_line_feature in cur_op_selected_features:
                            if line[resp_number_index]:
                                selected_numbers_feature[line[resp_number_index]] = cur_line_feature

                # read pcap file and get
                pcap = pyshark.FileCapture(dataset_path + pcap_file_name, display_filter=filter_condition, use_json=True,
                                              override_prefs={'ssl.keylog_file': dataset_path + key_file_name})
                for packet in pcap:
                    str_number = str(packet.number)
                    if str_number in selected_numbers_feature:
                        if selected_numbers_feature[str_number] not in feature_payloads_dict:
                            feature_payloads_dict[selected_numbers_feature[str_number]] = []
                        feature_payloads_dict[selected_numbers_feature[str_number]].append(format_tools.remove_string_by_some_pattern(get_payload_from_packet(packet)))
                pcap.close()

            feature_payloads_pattern = {}
            for key in feature_payloads_dict:
                feature_payloads_dict[key] = split_list_by_length(feature_payloads_dict[key])
                if key not in feature_payloads_pattern:
                    feature_payloads_pattern[key] = []
                for len_split_payloads in feature_payloads_dict[key]:
                    feature_payloads_pattern[key].append(format_tools.get_patterns_for_cases(len_split_payloads))

            with open(dataset_path + operation + "/payload_static.txt", "w") as f:
                f.write(json.dumps(feature_payloads_dict, indent=4))

            # get payload pattern
            with open(dataset_path + operation + "/payload_pattern.txt", "w") as f:
                f.write(json.dumps(feature_payloads_pattern, indent=4))


def get_new_op_class_for_response(new_pcapng_file_name, param_dict):
    """
    Giving a new pcapng file of an operation, get it's abstract class
    :param new_pcapng_file_name: pcapng_file under classifying, such as "SA_111.pcapng"
    :param param_dict: {op_name, start_time, end_time}
    :return: abstract class for response
    """
    mlog.log_func(mlog.LOG, "Parse and get new response...")
    pcapng_file_path = PACKET_ROOT_PATH + new_pcapng_file_name.split(".")[0] + "/" + new_pcapng_file_name
    keylog_file_path = pcapng_file_path[:-6] + "txt"

    # # read pcapng file
    # pcap = pyshark.FileCapture(pcapng_file_path, display_filter=FILTER_CONDITION,
    #                            override_prefs={'ssl.keylog_file': keylog_file_path})
    #
    # # for each packet, extract its header features and save in corresponding csv file
    # new_csv_name, new_file_header_features, packet_number = get_header_features(pcap, new_pcapng_file_name)
    # pcap.close()
    #
    # # get features from feature dataset, vectorize and mapping to word
    # dataset_imp_features, dataset_imp_cor_words = get_header_features_from_dataset(new_op_name)
    # total_features = dataset_imp_features + new_file_header_features
    # feature_vectors = vectorize_features(total_features)
    #
    # # mapping
    # ind_word = []
    # for mapping_index in range(len(dataset_imp_cor_words), len(total_features)):
    #     for finding_index in range(len(dataset_imp_features)):
    #         if cosine_similarity(feature_vectors[mapping_index], feature_vectors[finding_index]) > similarity_threshold:
    #             ind_word.append((mapping_index - len(dataset_imp_cor_words), dataset_imp_cor_words[finding_index]))
    #             break
    #
    # # save mapping result in csv file
    # with open(PACKET_ROOT_PATH + new_op_name + "/" + new_csv_name, "r") as file:
    #     reader = csv.reader(file)
    #     rows = list(reader)
    # rows[0].append("mapping_word")
    # for row_index, word in ind_word:
    #     rows[row_index + 1].append(word)
    # with open(PACKET_ROOT_PATH + new_op_name + "/" + new_csv_name, "w") as file:
    #     writer = csv.writer(file)
    #     writer.writerows(rows)
    #
    # # get pre-parse payloads
    # dataset_payloads_dict = get_payload_from_preprogress_dataset(new_op_name)
    #
    # # get correct word_line_dict
    # final_important_word_list = list(set([x[1] for x in ind_word]))
    # word_line_dict = get_important_packet_line_dict_by_important_word_for_cur_pcapng(new_op_name, final_important_word_list, new_pcapng_file_name)
    # word_line_dict = word_line_dict[new_pcapng_file_name.split(".")[0]]
    #
    # # save in csv file and get important packet.number
    # word_payload_dict = {}
    # number_word_dict = {}
    # with open(PACKET_ROOT_PATH + new_op_name + "/" + new_csv_name, "r") as file:
    #     reader = csv.reader(file)
    #     rows = list(reader)
    # rows[0].append("final_select")
    # for word, row_index in word_line_dict.items():
    #     row_index = int(row_index)
    #     rows[row_index].append("222")
    #
    #     if word not in word_payload_dict.keys():
    #         word_payload_dict[word] = []
    #     word_payload_dict[word].append([row_index, rows[row_index][0], rows[row_index][1]])
    #     word_payload_dict[word].append([""])
    #
    #     if rows[row_index][1] != "":
    #         number_word_dict[rows[row_index][1]] = word
    #     else:
    #         number_word_dict[rows[row_index][0]] = word
    #
    # with open(PACKET_ROOT_PATH + new_op_name + "/" + new_csv_name, "w") as file:
    #     writer = csv.writer(file)
    #     writer.writerows(rows)
    #
    # # read payload of important packets
    # pcap = pyshark.FileCapture(pcapng_file_path, display_filter=FILTER_CONDITION,
    #                            override_prefs={'ssl.keylog_file': keylog_file_path}, use_json=True)
    # for packet in pcap:
    #     if str(packet.number) in number_word_dict.keys():
    #         for finding_index in range(0, len(word_payload_dict[number_word_dict[str(packet.number)]]), 2):
    #             if str(packet.number) in word_payload_dict[number_word_dict[str(packet.number)]][finding_index]:
    #                 word_payload_dict[number_word_dict[str(packet.number)]][finding_index + 1][0] += ("," + get_payload_from_packet(packet))
    # pcap.close()
    #
    # # merge and split
    # word_number_dict = dataset_payloads_dict.copy()
    # word_number_dict.update({new_pcapng_file_name.split(".")[0]: word_payload_dict})
    #
    # entropy_threshold = 10
    # word_number_dict = format_payload_str_by_entropy_and_pattern(word_number_dict, get_important_words_from_dataset(new_op_name), entropy_threshold, get_new_resp_flag=True)
    #
    # # use entropy to get class of new pcapng file(or equal relative)
    # pcap_payload_list = []
    # for concrete_pcapng_name, word_payload_dict in word_number_dict.items():
    #     each_pcapng_payload_list = []
    #     word_payload_dict = format_tools.sort_dict_by_key(word_payload_dict)
    #     for word, value in word_payload_dict.items():
    #         payload_list = []
    #         for finding_index in range(1, len(value), 2):
    #             payload_list.append(value[finding_index])
    #         each_pcapng_payload_list.append(payload_list)
    #     pcap_payload_list.append(each_pcapng_payload_list)
    #
    # class_result_list = my_classify.use_total_important_word_for_classifying(new_op_name, pcap_payload_list)
    # ori_class_list = []
    # new_file_class = None
    # class_index = 0
    # for concrete_pcapng_name in word_number_dict.keys():
    #     if concrete_pcapng_name == new_pcapng_file_name.split(".")[0]:
    #         new_file_class = class_result_list[class_index]
    #     else:
    #         ori_class_list.append(class_result_list[class_index])
    #     class_index += 1
    # ori_class_list = list(set(ori_class_list))
    #
    # # if new class appear, add it to dataset
    # if new_file_class not in ori_class_list:
    #     # save string in csv file
    #     csv_file_path = PACKET_ROOT_PATH + new_op_name + "/" + new_csv_name
    #     new_header_name = "payload_str"
    #     with open(csv_file_path, "r") as file:
    #         reader = csv.reader(file)
    #         rows = list(reader)
    #     rows[0].append(new_header_name)
    #     for word in word_payload_dict.keys():
    #         for finding_index in range(0, len(word_payload_dict[word]), 2):
    #             line_number = int(word_payload_dict[word][finding_index][0])
    #             rows[line_number].append(word_payload_dict[word][finding_index + 1])
    #     with open(csv_file_path, "w") as file:
    #         writer = csv.writer(file)
    #         writer.writerows(rows)
    #
    #     # add to classify_result.json
    #     with open(PACKET_ROOT_PATH + new_op_name + "/classify_result.json", "r") as file:
    #         temp_class = json.load(file)
    #     temp_class[new_pcapng_file_name.split(".")[0]] = new_file_class
    #     with open(PACKET_ROOT_PATH + new_op_name + "/classify_result.json", "w") as file:
    #         file.write(json.dumps(temp_class, indent=4))
    #
    # mlog.log_func(mlog.LOG, "Parse finish, get response: " + new_file_class)
    # return new_file_class


if __name__ == "__main__":
    mlog.clear_log()

    import time

    start_time = time.time()
    # pre_parse(get_dataset_name_list())
    pre_parse(["manual_dataset_1708329730"])
    end_time = time.time()
    print("time: ", end_time - start_time)
    print("============================")

    # # read pcap file and get
    # dataset_path = PACKET_ROOT_PATH + "manual_dataset_1706001324/"
    # pcap = pyshark.FileCapture(dataset_path + "manual_dataset_1706001324.pcapng", use_json=True,
    #                            override_prefs={'ssl.keylog_file': dataset_path + "manual_dataset_1706001324.txt"})
    # for packet in pcap:
    #     # if "json" in packet:
    #     #     get_payload_from_packet(packet)
    #     if packet.number == "8696" or packet.number == 5619:
    #         get_payload_from_packet(packet)
    #         break
    # pcap.close()

    # start_time = time.time()
    # print(get_new_op_class_for_response(new_pcapng_file))  # 0
    # end_time = time.time()
    # print("time: ", end_time - start_time)
    # print("============================")

    # get_difference_for_analyse("DCU1")
