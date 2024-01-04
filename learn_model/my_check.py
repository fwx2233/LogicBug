import json
import os
import csv
import format_tools

ROOT_PATH = os.path.dirname(__file__)
PACKET_ROOT_PATH = ROOT_PATH + "/packets/"

fieldnames_of_csv = ["protocol", "request_method", "request_uri", "host", "authorization", "request|file_data",  # http request
                     "response_code", "response|file_data",   # http response
                     "hdrflags", "topic", "msg",  # mqtt
                     "request_length", "response_length"]  # udp
special_field = ["request_uri", "host"]


def check_word_mapping():
    op_name_list = os.listdir(PACKET_ROOT_PATH)

    word_feature_dict = {}
    feature_word_dict = {}

    for op_name in op_name_list:
        cur_op_folder_path = PACKET_ROOT_PATH + op_name + "/"
        file_list = os.listdir(cur_op_folder_path)
        csv_file_list = [x for x in file_list if ".csv" in x]

        # read csv file and get feature
        for csv_file in csv_file_list:
            with open(cur_op_folder_path + csv_file, "r") as file:
                reader = csv.reader(file)
                rows = list(reader)
                header = rows[0]

            for row in rows[1:]:
                feature_list = []
                word = row[header.index("mapping_word")]

                for field in fieldnames_of_csv:
                    field_index = header.index(field)
                    if field not in special_field:
                        feature_list.append(row[field_index])
                    elif field == "request_uri":
                        feat = '/'.join(row[field_index].split())
                        feature_list.append(feat)
                    elif field == "host":
                        feat = '.'.join(row[field_index].split())
                        feature_list.append(feat)

                fea_string = "$".join(feature_list)

                if word not in word_feature_dict:
                    word_feature_dict[word] = [fea_string]
                else:
                    word_feature_dict[word].append(fea_string)

                if fea_string not in feature_word_dict:
                    feature_word_dict[fea_string] = [word]
                else:
                    if word not in feature_word_dict[fea_string]:
                        feature_word_dict[fea_string].append(word)

    # get total line count
    total_line_count = 0
    for word in word_feature_dict:
        total_line_count += len(word_feature_dict[word])
    print("Total word: ", len(word_feature_dict.keys()))
    print("Total line: ", total_line_count)

    statistic_file = ROOT_PATH + "/statis.json"

    word_feature_dict = format_tools.sort_dict_by_key(word_feature_dict)
    feature_word_dict = format_tools.sort_dict_by_key(feature_word_dict)

    with open(ROOT_PATH + "/ttt.json", "w") as f:
        f.write(json.dumps(feature_word_dict, indent=4))

    # get the line count of each word and the set of line
    word_line_inter_count_dict = {}
    for word in word_feature_dict:
        if word not in word_line_inter_count_dict:
            word_line_inter_count_dict[word] = []

        word_line_inter_count_dict[word].append(len(word_feature_dict[word]))
        word_line_inter_count_dict[word].append(len(set(word_feature_dict[word])))
        word_line_inter_count_dict[word].append(list(set(word_feature_dict[word])))

        # print
        if len(set(word_feature_dict[word])) > 1:
            print(word, "line count:", word_line_inter_count_dict[word][0], "\tsingle class count:", word_line_inter_count_dict[word][1])
            for item in set(word_feature_dict[word]):
                print(item)
            print("=========================")

    with open(statistic_file, "w") as log_f:
        log_f.write(json.dumps(word_line_inter_count_dict, indent=4))


def find_word_csv_and_line(word, find_in_op_name=None):
    op_name_list = os.listdir(PACKET_ROOT_PATH)

    for op_name in op_name_list:
        if find_in_op_name:
            if op_name != find_in_op_name:
                continue

        cur_op_folder_path = PACKET_ROOT_PATH + op_name + "/"
        csv_list = [x for x in os.listdir(cur_op_folder_path) if ".csv" in x]

        find_flag = False
        for csv_file in csv_list:
            with open(cur_op_folder_path + csv_file, "r") as f:
                reader = csv.reader(f)
                rows = list(reader)
                word_index = rows[0].index("mapping_word")
                line_number = 1
                for row in rows[1:]:
                    if row[word_index] == word:
                        print(csv_file)
                        print("line_number:", line_number)
                        find_flag = True
                        break
                    line_number += 1
            if find_flag:
                break


def get_difference_for_analyse(op_name):
    class_file = PACKET_ROOT_PATH + op_name + "/classify_result.json"
    with open(class_file, "r") as file:
        class_result = json.load(file)

    result_pcapng_dict = {}
    for x, y in class_result.items():
        if y not in result_pcapng_dict.keys():
            result_pcapng_dict[y] = {}
            csv_file_path = PACKET_ROOT_PATH + op_name + "/" + x + ".csv"
            with open(csv_file_path, "r") as file:
                reader = csv.reader(file)
                rows = list(reader)
            final_select_index = rows[0].index("final_select")
            mapping_word_index = rows[0].index("mapping_word")
            payload_index = rows[0].index("payload_str")
            for row in rows:
                if final_select_index >= len(row):
                    continue
                if row[final_select_index] == "222":
                    result_pcapng_dict[y][row[mapping_word_index]] = row[payload_index]

    for word in list(result_pcapng_dict.values())[0].keys():
        print(word)
        for pcapng in result_pcapng_dict.keys():
            print(pcapng, result_pcapng_dict[pcapng][word])


def important_word_number_for_each_op():
    word_file_name = "important_words.txt"
    op_name_list = os.listdir(PACKET_ROOT_PATH)

    word_imp_count_dict = {}
    total_list = []

    for op_name in op_name_list:
        print(op_name, end=": ")
        cur_op_path = PACKET_ROOT_PATH + op_name + "/"
        with open(cur_op_path + word_file_name, "r") as file:
            word_list = file.readline().split(" | ")
            word_imp_count_dict[op_name] = len(word_list)
            print(len(word_list))
            total_list.extend(word_list)

    total_list = set(total_list)
    print("Total word:", len(total_list))


if __name__ == "__main__":
    # check_word_mapping()
    # find_word_csv_and_line("word1188")
    important_word_number_for_each_op()
