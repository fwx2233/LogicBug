import json
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction.text import CountVectorizer
import jsonlayer_parser, format_tools
import pyshark
import os
import csv
from log import mlog
from protocol_feature import protocol_feature_dict, abstract_feature_list
import numpy as np
import re
import my_classify
import Levenshtein
from collections import defaultdict

ROOT_PATH = os.path.dirname(__file__)
PACKET_ROOT_PATH = ROOT_PATH + "/packets/"

FILTER_CONDITION = "(http or mqtt or ((udp and !dns) and (udp and !mdns))) and !bootp and !(ip.addr == 10.42.0.1) and !coap"
ABSTRACT_FEATURE = "HAS_FEATURE"

# similarity threshold of documents. if larger than similarity_threshold, regard as the same word
similarity_threshold = 0.9
threshold_multiplier = 1

test_flag = False
no_need_mapping_flag = False

all_packet_folder_list = os.listdir(PACKET_ROOT_PATH)
pcapng_order_and_length_dict = {}
result_document_of_each_pcapng = {}
word_for_each_pcapng = {}

fieldnames_of_csv = ["number", "response_number", "udp_stream", "ip1", "ip2", "port1", "port2",
                     "protocol", "request_layer_counts", "response_layer_counts", "uri_word_counts"]
# not_feature_list = ["number", "response_number", "udp_stream", "ip1", "ip2", "port1"]
not_feature_list = ["number", "response_number", "udp_stream", "ip1", "ip2", "port1", "port2"]
disabled_words = ["HTTP response", "Group:", "Date:", "Request:", "Response:", " in frame:", "Time since request:",
                  "Prev ", "prev_", "HTTP request", "Severity level:", "Expert Info ", "Status Code Description:",
                  "request_number:", "request_in:", "response_number:"]
enhance_feature_dict = {
    "request_method": 10,
    "topic": 0,
    "request_uri": 0,
    "uri_word_counts": 8,
}
start_index = len(fieldnames_of_csv)


common_field_count = len(fieldnames_of_csv)
for protocol_name in protocol_feature_dict.keys():
    fieldnames_of_csv.extend(protocol_feature_dict[protocol_name])


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


def get_important_packet_line_dict_by_important_word_for_cur_pcapng(op_name, final_important_word_list, new_pcap_file_name=None):
    file_list = os.listdir(PACKET_ROOT_PATH + op_name + "/")
    if not new_pcap_file_name:
        pcapng_file_list = [f for f in file_list if "pcapng" in f]
    else:
        with open(PACKET_ROOT_PATH + op_name + "/classify_result.json", "r") as f:
            classify_result = json.load(f)
        pcapng_file_list = list(classify_result.keys())
        pcapng_file_list.append(new_pcap_file_name)

    # return result
    remove_list = []

    # initialize
    pcap_word_lines_dict = {}
    for pcapng_name in pcapng_file_list:
        pcapng_name = pcapng_name.split(".")[0]
        pcap_word_lines_dict[pcapng_name] = {}
        cur_csv_path = PACKET_ROOT_PATH + op_name + '/' + pcapng_name + ".csv"

        # read csv file
        with open(cur_csv_path, "r") as f:
            reader = csv.reader(f)
            rows = list(reader)
        # rows[0].append("final_select")
        mapping_word_index = rows[0].index("mapping_word")

        # get each word_line, if the same line appear more than once, use the latest line cover the old
        # So we regard the line string as key, line number as the value
        for row in rows[1:]:
            if mapping_word_index >= len(row):
                continue
            if row[mapping_word_index] in final_important_word_list:
                if row[mapping_word_index] not in pcap_word_lines_dict[pcapng_name].keys():
                    pcap_word_lines_dict[pcapng_name][row[mapping_word_index]] = {}
                # if the word has appeared, save the latest one
                pcap_word_lines_dict[pcapng_name][row[mapping_word_index]][",".join(row[start_index:mapping_word_index])] = rows.index(row)

    for word in final_important_word_list:
        line_count_dict = defaultdict(int)
        for pcapng_name in pcap_word_lines_dict.keys():
            for line in pcap_word_lines_dict[pcapng_name][word].keys():
                line_count_dict[line] += 1
        # select
        if len(line_count_dict.keys()) > 1:
            # when more than one packet was mapped to the same word, select the most one
            line_count_dict = dict(sorted(line_count_dict.items(), key=lambda x: x[1], reverse=True))
            keep_line = list(line_count_dict.keys())[0]
            for pcapng_name in pcap_word_lines_dict.keys():
                if keep_line in pcap_word_lines_dict[pcapng_name][word].keys():
                    keep_line_number = pcap_word_lines_dict[pcapng_name][word][keep_line]
                    pcap_word_lines_dict[pcapng_name][word] = {}
                    pcap_word_lines_dict[pcapng_name][word][keep_line] = keep_line_number
                else:
                    remove_list.append(pcapng_name)

    # remove other line
    for pcapng_name in set(remove_list):
        del pcap_word_lines_dict[pcapng_name]

    for pcapng_name in pcap_word_lines_dict.keys():
        for word in pcap_word_lines_dict[pcapng_name].keys():
            line = list(pcap_word_lines_dict[pcapng_name][word].keys())[0]
            pcap_word_lines_dict[pcapng_name][word] = pcap_word_lines_dict[pcapng_name][word][line]
    return pcap_word_lines_dict


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
    # vectorizer = TfidfVectorizer()
    vectorizer = CountVectorizer()
    feature_vectors = vectorizer.fit_transform(features)
    return feature_vectors


def get_header_features(pcap, pcapng_file_name):
    pcap_feature_dict_list = []
    packet_num = 0
    merge_flag = False
    for packet in pcap:
        packet_feature_dict = {}
        # get basic info
        packet_feature_dict["number"] = packet.number
        if "ip" not in packet:
            mlog.log_func(mlog.ERROR, "packet " + str(packet.number) + " do not have ip layer")
            exit(2)
        packet_feature_dict["ip1"] = packet.ip.src
        packet_feature_dict["ip2"] = packet.ip.dst
        packet_feature_dict["port1"] = packet[packet.transport_layer].srcport
        packet_feature_dict["port2"] = packet[packet.transport_layer].dstport
        packet_feature_dict["request_layer_counts"] = len(list(packet.layers))
        packet_feature_dict["udp_stream"] = ""

        # get features for each protocol
        for protocol_name in protocol_feature_dict.keys():
            if protocol_name != "record":
                if protocol_name in packet:
                    packet_feature_dict["protocol"] = protocol_name
                    cur_layer = packet[protocol_name]
                    for field_name in protocol_feature_dict[protocol_name]:
                        if '|' not in field_name:
                            if field_name in cur_layer.field_names:
                                abs_name = protocol_name + '.' + field_name
                                if abs_name in abstract_feature_list:
                                    packet_feature_dict[field_name] = ABSTRACT_FEATURE + "|" + field_name
                                else:
                                    temp_str = format_tools.format_uri_header_features(cur_layer.get_field(field_name))
                                    str_split = temp_str.split()
                                    if len(str_split) > 1:
                                        result_str = ""
                                        for sub_str in str_split:
                                            if format_tools.check_if_string_is_id_class(sub_str):
                                                result_str += (" id_len_" + str(len(sub_str)))
                                            else:
                                                result_str += (" " + sub_str)
                                    else:
                                        result_str = temp_str
                                    packet_feature_dict[field_name] = result_str
                            else:
                                packet_feature_dict[field_name] = None
                        else:
                            prefix = field_name.split('|')[0]
                            field_name_in_layer = field_name.split('|')[-1]
                            if prefix in cur_layer.field_names and field_name_in_layer in cur_layer.field_names:
                                abs_name = protocol_name + '.' + field_name
                                if abs_name in abstract_feature_list:
                                    packet_feature_dict[field_name] = ABSTRACT_FEATURE + "|" + field_name + "|" + packet.highest_layer
                                else:
                                    temp_str = format_tools.format_uri_header_features(cur_layer.get_field(field_name))
                                    str_split = temp_str.split()
                                    if len(str_split) > 1:
                                        result_str = ""
                                        for sub_str in str_split:
                                            if format_tools.check_if_string_is_id_class(sub_str):
                                                result_str += (" id_len_" + str(len(sub_str)))
                                            else:
                                                result_str += (" " + sub_str)
                                    else:
                                        result_str = temp_str
                                    packet_feature_dict[field_name] = result_str
                            else:
                                packet_feature_dict[field_name] = None

                    if "request_uri" in cur_layer.field_names:
                        packet_feature_dict["uri_word_counts"] = len(packet_feature_dict["request_uri"].split())

                    # if this packet is the response of any packet
                    if "response" in cur_layer.field_names and "request_in" in cur_layer.field_names:
                        # merge this response to request
                        for index in range(len(pcap_feature_dict_list) - 1, -1, -1):
                            if pcap_feature_dict_list[index]["number"] == cur_layer.request_in:
                                pcap_feature_dict_list[index]["response_number"] = packet_feature_dict["number"]
                                pcap_feature_dict_list[index]["response_layer_counts"] = len(list(packet.layers))

                                # merge features
                                for feature_name in list(packet_feature_dict.keys())[common_field_count:]:
                                    if packet_feature_dict[feature_name]:
                                        pcap_feature_dict_list[index][feature_name] = packet_feature_dict[feature_name]
                        # next circle
                        merge_flag = True

                    if protocol_name == "udp" and "stream" in cur_layer.field_names:
                        for index in range(len(pcap_feature_dict_list) - 1, -1, -1):
                            if (pcap_feature_dict_list[index]["udp_stream"] == str(cur_layer.stream)
                                    and packet_feature_dict["ip1"] == pcap_feature_dict_list[index]["ip2"]
                                    and packet_feature_dict["port1"] == pcap_feature_dict_list[index]["port2"]):
                                pcap_feature_dict_list[index]["response_number"] = packet_feature_dict["number"]
                                pcap_feature_dict_list[index]["response_length"] = cur_layer.length
                                merge_flag = True
                                break
                        if not merge_flag:
                            packet_feature_dict["udp_stream"] = str(cur_layer.stream)
                            packet_feature_dict["request_length"] = cur_layer.length

                else:
                    for field_name in protocol_feature_dict[protocol_name]:
                        packet_feature_dict[field_name] = None

        if not merge_flag:
            pcap_feature_dict_list.append(packet_feature_dict)
            packet_num += 1

        merge_flag = False

    # save csv file
    csv_name = PACKET_ROOT_PATH + pcapng_file_name.split("_")[0] + "/" + pcapng_file_name.split(".")[0] + ".csv"
    with open(csv_name, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames_of_csv)
        writer.writeheader()
        writer.writerows(pcap_feature_dict_list)
    csv_name = csv_name.split("/")[-1]

    # get features for mapping
    # remove some fields
    temp_fieldnames_of_csv = []
    for n_fea in fieldnames_of_csv:
        if n_fea not in not_feature_list:
            temp_fieldnames_of_csv.append(n_fea)

    features = get_header_features_from_csv_files_and_enhance([csv_name], temp_fieldnames_of_csv, enhance_feature_dict)

    return csv_name, features, packet_num


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

    if highest_layer_name == "data":  # udp
        ascii_str_list = str(packet.data.data).split(":")
        # result_str = ""
        # for ascii_value in ascii_str_list:
        #     try:
        #         char = chr(int(ascii_value, 16))
        #         result_str += char
        #     except ValueError:
        #         mlog.log_func(mlog.ERROR, "Invalid ASCII value:" + ascii_value)
        #         exit(2)
        # result_str = format_tools.remove_split_characters(result_str)
        # result_str = ",".join(format_tools.remove_string_by_some_pattern(result_str.split(",")))
        result_str = ",".join(ascii_str_list)
        return result_str

    packet_highest_payload_str = str(packet.get_multiple_layers(highest_layer_name)[0]).replace(
        "Layer " + highest_layer_name.upper() + "\n:", "")
    if highest_layer_name == "json":
        packet_highest_payload_str = jsonlayer_parser.parse_main(packet_highest_payload_str)
    else:
        packet_highest_payload_str = "\n".join(
            format_tools.remove_http_stop_words(sorted(packet_highest_payload_str.split("\n")), disabled_words))
    packet_highest_payload_str = format_tools.remove_split_characters(packet_highest_payload_str)
    packet_highest_payload_str = ",".join(format_tools.remove_string_by_some_pattern(packet_highest_payload_str.split(",")))
    return packet_highest_payload_str


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
        length = len(strings[temp_index])
        length_dict[length].append([temp_index, strings[temp_index]])

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


def pre_parse():
    '''
    ================================ module 1 ================================
    Read pcapng files and extract features.
    Save features in corresponding csv file.
    '''
    mlog.log_func(mlog.LOG, "Start reading pcapng files and extracting features...")

    temp_count = 0
    total_pcapng_file_list = []
    for operation_folder in all_packet_folder_list:
        abs_operation_folder = PACKET_ROOT_PATH + operation_folder + "/"
        if not os.path.isdir(abs_operation_folder):
            continue
        pcapng_file_list = os.listdir(abs_operation_folder)
        for item in pcapng_file_list:
            if item.split('.')[-1] == "pcapng":
                keylog_file = item.split('.')[0] + ".txt"
                if not os.path.exists(abs_operation_folder + keylog_file):
                    continue

                total_pcapng_file_list.append(item.split('.')[0])
                # read packet and it's key log file
                temp_count += 1
                mlog.log_func(mlog.LOG, str(temp_count) + " Reading pcapng file:" + item)
                pcap = pyshark.FileCapture(abs_operation_folder + item, display_filter=FILTER_CONDITION, override_prefs={'ssl.keylog_file':abs_operation_folder + keylog_file})
                pcapng_order_and_length_dict[item.split('.')[0]] = get_header_features(pcap, item)[-1]
                pcap.close()

    '''
    ================================ module 2 ================================
    Use features to fit and vectorize the document. 
    Mapping the document to the same word if similarity between two vectors is larger than threshold.
    '''
    mlog.log_func(mlog.LOG, "Fitting vectors and mapping...")

    # remove some fields
    temp_fieldnames_of_csv = []
    for n_fea in fieldnames_of_csv:
        if n_fea not in not_feature_list:
            temp_fieldnames_of_csv.append(n_fea)
    features = get_header_features_from_csv_files_and_enhance(total_pcapng_file_list, temp_fieldnames_of_csv, enhance_feature_dict)
    tfidf_matrix = vectorize_features(features)
    mlog.log_func(mlog.LOG, "Total packets and the shape of vector matrix: " + str(tfidf_matrix.shape))
    mlog.log_func(mlog.LOG, "Similarity threshold: " + str(similarity_threshold))
    mlog.log_func(mlog.LOG, "Enhance count: ")
    mlog.log_dict_func(mlog.LOG, enhance_feature_dict)

    # get similarity matrix
    similarity_matrix = cosine_similarity(tfidf_matrix)

    # Map vectors to words and ensure that similar vectors are the same word
    # dictionary to save mapping
    vector_mapping = {}

    max_word = ""
    for i in range(tfidf_matrix.shape[0]):
        if i in vector_mapping.keys():
            continue

        # mapping to a new word
        current_string = "word"+str(i)
        max_word = current_string

        for j in range(i, tfidf_matrix.shape[0]):
            if j in vector_mapping:
                continue

            # compute the similarity between two vector
            similarity = similarity_matrix[i, j]

            # mapping to the same word if computing value larger than similarity threshold
            if similarity >= similarity_threshold:
                vector_mapping[j] = current_string

    mlog.log_func(mlog.LOG, "Total packets: " + max_word[4:])

    # save word in corresponding csv file
    total_index = 0
    for (docu_name, docu_num) in pcapng_order_and_length_dict.items():
        op_name = docu_name[:0 - len(docu_name.split('_')[-1]) - 1]
        if op_name not in result_document_of_each_pcapng.keys():
            result_document_of_each_pcapng[op_name] = {}
            result_document_of_each_pcapng[op_name]["aggregation"] = ""
        result_document_of_each_pcapng[op_name][docu_name] = ""

        # add new column for word
        cur_csv_path = PACKET_ROOT_PATH + op_name + '/' + docu_name + '.csv'
        new_column_name = "mapping_word"
        with open(cur_csv_path, "r") as f:
            reader = csv.reader(f)
            rows = list(reader)
        header = rows[0]
        header.append(new_column_name)
        for i in range(docu_num):
            result_document_of_each_pcapng[op_name][docu_name] += (vector_mapping[total_index] + ' ')
            result_document_of_each_pcapng[op_name]["aggregation"] += result_document_of_each_pcapng[op_name][docu_name]
            rows[i + 1].append(vector_mapping[total_index])
            total_index += 1

        with open(cur_csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(rows)

    # free the memory
    vector_mapping.clear()

    '''
    ================================ module 3 ================================
    For each pcapng file, filter it's unimportant packet, read it's important packet and vectorize them.
    '''
    # get result_document_of_each_pcapng from csv file
    for pcapng_name in total_pcapng_file_list:
        op_name = pcapng_name.split('_')[0]
        abs_path = PACKET_ROOT_PATH + op_name + '/' + pcapng_name + ".csv"
        if op_name not in result_document_of_each_pcapng.keys():
            result_document_of_each_pcapng[op_name] = {}
            result_document_of_each_pcapng[op_name]["aggregation"] = ""
        result_document_of_each_pcapng[op_name][pcapng_name] = ""
        with open(abs_path, "r") as file:
            reader = csv.reader(file)
            header = next(reader)
            mapping_word_index = header.index("mapping_word")
            for line in list(reader)[1:]:
                result_document_of_each_pcapng[op_name][pcapng_name] += (' ' + line[mapping_word_index])
            result_document_of_each_pcapng[op_name]["aggregation"] += (' ' + result_document_of_each_pcapng[op_name][pcapng_name])

    # aggregation and fit vector
    aggre_list = []
    for op_name, value in result_document_of_each_pcapng.items():
        if "aggregation" in value.keys():
            aggre_list.append(value["aggregation"])

    vectorizer = TfidfVectorizer()
    tfidf_matrix = vectorizer.fit_transform(aggre_list)

    # get feature words list and calculate the threshold
    feature_names = vectorizer.get_feature_names_out()
    tfidf_value = tfidf_matrix.toarray().sum(axis=0).tolist()

    # get total word counts
    hist, bin_edges = np.histogram(tfidf_value, bins=10)
    total_count = np.sum(hist)
    select_value_count = 0
    for i in range(len(hist)):
        select_value_count += hist[i]
        if select_value_count/total_count > 0.6:
            high_line = bin_edges[i + 1]
            break
    mlog.log_func(mlog.LOG, "Total words: " + str(total_count))
    filtered_data = [value for value in tfidf_value if value <= high_line]
    # print(np.mean(filtered_data))

    min_threshold = np.mean(filtered_data)
    mlog.log_func(mlog.LOG, "TF-IDF threshold = (" + str(min_threshold) + " ~ " + "max)")

    for temp_index in range(len(feature_names)):
        print(feature_names[temp_index], tfidf_value[temp_index])

    important_words = []
    for temp_index in range(len(feature_names)):
        if tfidf_value[temp_index] >= min_threshold:
            important_words.append(feature_names[temp_index])
    important_words = list(set(important_words))
    mlog.log_func(mlog.LOG, "Key words selected from (mean ~ max): " + str(len(important_words)))

    final_important_word_dict = get_final_important_words_for_each_op(list(result_document_of_each_pcapng.keys()), important_words)

    for op_name in final_important_word_dict.keys():
        final_import_word_list = final_important_word_dict[op_name]
        pcap_word_line_dict = get_important_packet_line_dict_by_important_word_for_cur_pcapng(op_name, final_import_word_list)
        final_import_word_list = list(pcap_word_line_dict[list(pcap_word_line_dict.keys())[0]].keys())
        with open(PACKET_ROOT_PATH + op_name + "/important_words.txt", "w") as imp_word_file:
            imp_word_file.write(' | '.join(final_import_word_list))
        mlog.log_func(mlog.LOG, "Final important words in " + op_name + ": " + ' | '.join(final_import_word_list))

        # save in csv files and get packet number(req and resp)
        word_number_dict = {}
        for pcapng_name in pcap_word_line_dict.keys():
            cur_csv_path = PACKET_ROOT_PATH + op_name + '/' + pcapng_name + ".csv"

            with open(cur_csv_path, "r") as f:
                reader = csv.reader(f)
                rows = list(reader)
            rows[0].append("final_select")
            mapping_word_index = rows[0].index("mapping_word")

            number_word_dict = {}
            if pcapng_name not in word_number_dict.keys():
                word_number_dict[pcapng_name] = {}
            for word in pcap_word_line_dict[pcapng_name].keys():
                i = pcap_word_line_dict[pcapng_name][word]
                rows[i].append("222")

                if rows[i][mapping_word_index] not in word_number_dict[pcapng_name]:
                    word_number_dict[pcapng_name][rows[i][mapping_word_index]] = []
                word_number_dict[pcapng_name][rows[i][mapping_word_index]].append([i, rows[i][0], rows[i][1]])
                word_number_dict[pcapng_name][rows[i][mapping_word_index]].append([""])

                if rows[i][1] != "":
                    number_word_dict[rows[i][1]] = word
                else:
                    number_word_dict[rows[i][0]] = word

            with open(cur_csv_path, "w") as f:
                writer = csv.writer(f)
                writer.writerows(rows)

            '''
            deep packet analyse for classify
            '''
            cur_pcapng_path = cur_csv_path[:-3] + "pcapng"
            cur_key_path = cur_csv_path[:-3] + "txt"

            pcap = pyshark.FileCapture(cur_pcapng_path, display_filter=FILTER_CONDITION,
                                       override_prefs={'ssl.keylog_file': cur_key_path}, use_json=True)
            for packet in pcap:
                if str(packet.number) in number_word_dict.keys():
                    cor_word = number_word_dict[str(packet.number)]
                    for finding_index in range(0, len(word_number_dict[pcapng_name][cor_word]), 2):
                        if str(packet.number) in word_number_dict[pcapng_name][cor_word][finding_index]:
                            word_number_dict[pcapng_name][cor_word][finding_index + 1][0] += (
                                    "," + get_payload_from_packet(packet))
            pcap.close()

        '''
        ================================ module 4 ================================
        For each pcapng file, calculate the entropy of the same field in corresponding packet(vectorized in the same word)
        filter out the field which has obviously higher than others, such as "timestamp".
        '''
        # use abstract str to exchange field which has high entropy and pattern
        sig_threshold = 20
        word_number_dict = format_payload_str_by_entropy_and_pattern(word_number_dict, final_import_word_list, sig_threshold)

        for pcapng_name in word_number_dict.keys():
            # save payload in csv file
            csv_file_path = PACKET_ROOT_PATH + pcapng_name.split("_")[0] + "/" + pcapng_name + ".csv"
            new_header_name = "payload_str"
            with open(csv_file_path, "r") as file:
                reader = csv.reader(file)
                rows = list(reader)
            rows[0].append(new_header_name)

            for word in word_number_dict[pcapng_name]:
                for finding_index in range(0, len(word_number_dict[pcapng_name][word]), 2):
                    line_number = int(word_number_dict[pcapng_name][word][finding_index][0])
                    rows[line_number].append(word_number_dict[pcapng_name][word][finding_index + 1])

            with open(csv_file_path, "w") as file:
                writer = csv.writer(file)
                writer.writerows(rows)

        # classify
        pcap_payload_list = []
        for concrete_pcapng_name, word_payload_dict in word_number_dict.items():
            each_pcapng_payload_list = []
            word_payload_dict = format_tools.sort_dict_by_key(word_payload_dict)
            for word, value in word_payload_dict.items():
                payload_list = []
                for finding_index in range(1, len(value), 2):
                    payload_list.append(value[finding_index])
                each_pcapng_payload_list.append(payload_list)
            pcap_payload_list.append(each_pcapng_payload_list)

        class_result_list = my_classify.use_total_important_word_for_classifying(op_name, pcap_payload_list)
        result_dict = {}
        class_index = 0
        for concrete_pcapng_name, word_payload_dict in word_number_dict.items():
            result_dict[concrete_pcapng_name] = class_result_list[class_index]
            class_index += 1

        result_dict = format_tools.sort_dict_by_key(result_dict)

        result_json_file_path = PACKET_ROOT_PATH + op_name + "/classify_result.json"
        with open(result_json_file_path, "w") as f:
            f.write(json.dumps(result_dict, indent=4))


def get_new_op_class_for_response(new_pcapng_file_name):
    """
    Giving a new pcapng file of an operation, get it's abstract class
    :param new_pcapng_file_name: pcapng_file under classifying, such as "SA_111.pcapng"
    :return: abstract class for response
    """
    mlog.log_func(mlog.LOG, "Parse new pcapng_file: " + new_pcapng_file_name + " ......")
    new_op_name = new_pcapng_file_name.split("_")[0]
    pcapng_file_path = PACKET_ROOT_PATH + new_op_name + "/" + new_pcapng_file_name
    keylog_file_path = pcapng_file_path[:-6] + "txt"

    # read pcapng file
    pcap = pyshark.FileCapture(pcapng_file_path, display_filter=FILTER_CONDITION,
                               override_prefs={'ssl.keylog_file': keylog_file_path})

    # for each packet, extract its header features and save in corresponding csv file
    new_csv_name, new_file_header_features, packet_number = get_header_features(pcap, new_pcapng_file_name)
    pcap.close()

    # get features from feature dataset, vectorize and mapping to word
    dataset_imp_features, dataset_imp_cor_words = get_header_features_from_dataset(new_op_name)
    total_features = dataset_imp_features + new_file_header_features
    feature_vectors = vectorize_features(total_features)

    # mapping
    ind_word = []
    for mapping_index in range(len(dataset_imp_cor_words), len(total_features)):
        for finding_index in range(len(dataset_imp_features)):
            if cosine_similarity(feature_vectors[mapping_index], feature_vectors[finding_index]) > similarity_threshold:
                ind_word.append((mapping_index - len(dataset_imp_cor_words), dataset_imp_cor_words[finding_index]))
                break

    # save mapping result in csv file
    with open(PACKET_ROOT_PATH + new_op_name + "/" + new_csv_name, "r") as file:
        reader = csv.reader(file)
        rows = list(reader)
    rows[0].append("mapping_word")
    for row_index, word in ind_word:
        rows[row_index + 1].append(word)
    with open(PACKET_ROOT_PATH + new_op_name + "/" + new_csv_name, "w") as file:
        writer = csv.writer(file)
        writer.writerows(rows)

    # get pre-parse payloads
    dataset_payloads_dict = get_payload_from_preprogress_dataset(new_op_name)

    # get correct word_line_dict
    final_important_word_list = list(set([x[1] for x in ind_word]))
    word_line_dict = get_important_packet_line_dict_by_important_word_for_cur_pcapng(new_op_name, final_important_word_list, new_pcapng_file_name)
    word_line_dict = word_line_dict[new_pcapng_file_name.split(".")[0]]

    # save in csv file and get important packet.number
    word_payload_dict = {}
    number_word_dict = {}
    with open(PACKET_ROOT_PATH + new_op_name + "/" + new_csv_name, "r") as file:
        reader = csv.reader(file)
        rows = list(reader)
    rows[0].append("final_select")
    for word, row_index in word_line_dict.items():
        row_index = int(row_index)
        rows[row_index].append("222")

        if word not in word_payload_dict.keys():
            word_payload_dict[word] = []
        word_payload_dict[word].append([row_index, rows[row_index][0], rows[row_index][1]])
        word_payload_dict[word].append([""])

        if rows[row_index][1] != "":
            number_word_dict[rows[row_index][1]] = word
        else:
            number_word_dict[rows[row_index][0]] = word

    with open(PACKET_ROOT_PATH + new_op_name + "/" + new_csv_name, "w") as file:
        writer = csv.writer(file)
        writer.writerows(rows)

    # read payload of important packets
    pcap = pyshark.FileCapture(pcapng_file_path, display_filter=FILTER_CONDITION,
                               override_prefs={'ssl.keylog_file': keylog_file_path}, use_json=True)
    for packet in pcap:
        if str(packet.number) in number_word_dict.keys():
            for finding_index in range(0, len(word_payload_dict[number_word_dict[str(packet.number)]]), 2):
                if str(packet.number) in word_payload_dict[number_word_dict[str(packet.number)]][finding_index]:
                    word_payload_dict[number_word_dict[str(packet.number)]][finding_index + 1][0] += ("," + get_payload_from_packet(packet))
    pcap.close()

    # merge and split
    word_number_dict = dataset_payloads_dict.copy()
    word_number_dict.update({new_pcapng_file_name.split(".")[0]: word_payload_dict})

    entropy_threshold = 10
    word_number_dict = format_payload_str_by_entropy_and_pattern(word_number_dict, get_important_words_from_dataset(new_op_name), entropy_threshold, get_new_resp_flag=True)

    # use entropy to get class of new pcapng file(or equal relative)
    pcap_payload_list = []
    for concrete_pcapng_name, word_payload_dict in word_number_dict.items():
        each_pcapng_payload_list = []
        word_payload_dict = format_tools.sort_dict_by_key(word_payload_dict)
        for word, value in word_payload_dict.items():
            payload_list = []
            for finding_index in range(1, len(value), 2):
                payload_list.append(value[finding_index])
            each_pcapng_payload_list.append(payload_list)
        pcap_payload_list.append(each_pcapng_payload_list)

    class_result_list = my_classify.use_total_important_word_for_classifying(new_op_name, pcap_payload_list)
    ori_class_list = []
    new_file_class = None
    class_index = 0
    for concrete_pcapng_name in word_number_dict.keys():
        if concrete_pcapng_name == new_pcapng_file_name.split(".")[0]:
            new_file_class = class_result_list[class_index]
        else:
            ori_class_list.append(class_result_list[class_index])
        class_index += 1
    ori_class_list = list(set(ori_class_list))

    # if new class appear, add it to dataset
    if new_file_class not in ori_class_list:
        # save string in csv file
        csv_file_path = PACKET_ROOT_PATH + new_op_name + "/" + new_csv_name
        new_header_name = "payload_str"
        with open(csv_file_path, "r") as file:
            reader = csv.reader(file)
            rows = list(reader)
        rows[0].append(new_header_name)
        for word in word_payload_dict.keys():
            for finding_index in range(0, len(word_payload_dict[word]), 2):
                line_number = int(word_payload_dict[word][finding_index][0])
                rows[line_number].append(word_payload_dict[word][finding_index + 1])
        with open(csv_file_path, "w") as file:
            writer = csv.writer(file)
            writer.writerows(rows)

        # add to classify_result.json
        with open(PACKET_ROOT_PATH + new_op_name + "/classify_result.json", "r") as file:
            temp_class = json.load(file)
        temp_class[new_pcapng_file_name.split(".")[0]] = new_file_class
        with open(PACKET_ROOT_PATH + new_op_name + "/classify_result.json", "w") as file:
            file.write(json.dumps(temp_class, indent=4))

    mlog.log_func(mlog.LOG, "Parse finish, get response: " + new_file_class)
    return new_file_class


if __name__ == "__main__":
    mlog.clear_log()

    import time

    start_time = time.time()
    pre_parse()
    end_time = time.time()
    print("time: ", end_time - start_time)
    print("============================")

    # new_pcapng_file = "SAU1CWRU2_1701697275.pcapng"
    # with open(PACKET_ROOT_PATH + new_pcapng_file.split("_")[0] + "/classify_result.json", "r") as file:
    #     classify_json = json.load(file)
    # if new_pcapng_file.split(".")[0] in classify_json.keys():
    #     classify_json.pop(new_pcapng_file.split(".")[0])
    #     with open(PACKET_ROOT_PATH + new_pcapng_file.split("_")[0] + "/classify_result.json", "w") as file:
    #         file.write(json.dumps(classify_json, indent=4))
    #
    # start_time = time.time()
    # print(get_new_op_class_for_response(new_pcapng_file))  # 0
    # end_time = time.time()
    # print("time: ", end_time - start_time)
    # print("============================")

    # get_difference_for_analyse("DCU1")
