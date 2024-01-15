import csv
import re
import os


def filter_some_strings_by_re(string):
    patterns = [r'"*\b(time|date|timestamp)\b"*:*',
                r'\d{1,2} \w{3} \d{4} \d{2}:\d{2}:\d{2} \w{3}',
                r'[a-zA-Z0-9]*time[a-zA-Z0-9]*',
                r'"*\b(seq)\b"*:*',
                r'"picture.*":',
                r'"award(s)?_.*":']
    for pattern in patterns:
        if re.search(pattern, string, re.IGNORECASE):
            return True
    return False


def remove_string_by_some_pattern(strings):
    for reverse_index in range(len(strings) - 1, -1, -1):
        if filter_some_strings_by_re(strings[reverse_index]):
            strings[reverse_index] = "--pattern-string--"
    return strings


def get_diff_index_in_list(under_test_list):
    diff_index = []
    for index in range(len(under_test_list[0])):
        item_set = set()
        for item in under_test_list:
            item_set.add(item[index])

        if len(item_set) > 1:
            diff_count = len(item_set)
            if diff_count >= len(under_test_list) / 2:
                diff_index.append(index)

    return diff_index


def remove_blank_str(result_str, split_char):
    result_str = result_str.split(split_char)
    for reversed_index in range(len(result_str) - 1, -1, -1):
        if result_str[reversed_index] == "":
            result_str.pop(reversed_index)
    return split_char.join(result_str)


def remove_split_characters(result_str):
    split_char = ","
    replacements = {"\n": ",",
                    "[": ",",
                    "]": ",",
                    "{": ",",
                    "}": ",",
                    "\r": "",
                    "\t": ""}
    for old_str, new_str in replacements.items():
        result_str = result_str.replace(old_str, new_str)
    result_str = remove_blank_str(result_str, split_char)
    return result_str


def simply_format_header_feature(header_str: str):
    # keep the part before the "?"
    header_str = header_str.split("?")[0]

    return header_str


def read_all_uri_and_get_pattern(csv_file_list: list):
    """
    Get all kinds uri from csv files, and calculate entropy to get uri pattern
    :param csv_file_list: csv files under reading
    :return: uri pattern list
    """
    uri_split_str_list_dict = {}
    topic_split_str_list_dict = {}
    for csv_file_name in csv_file_list:
        op_name = csv_file_name.split('_')[0]
        cur_folder_path = os.path.dirname(__file__) + "/packets/" + op_name + '/'
        with open(cur_folder_path + csv_file_name, "r") as f:
            reader = csv.reader(f)
            header = next(reader)
            protocol_index = header.index("protocol")
            uri_index = header.index("request_uri")
            topic_index = header.index("topic")
            for line in list(reader)[1:]:
                if line[protocol_index] == "http":
                    if str(len(line[uri_index].split('/'))) not in uri_split_str_list_dict:
                        uri_split_str_list_dict[str(len(line[uri_index].split('/')))] = {str(len(line[uri_index])): [line[uri_index]]}
                    else:
                        if str(len(line[uri_index])) not in uri_split_str_list_dict[str(len(line[uri_index].split('/')))]:
                            uri_split_str_list_dict[str(len(line[uri_index].split('/')))][str(len(line[uri_index]))] = [line[uri_index]]
                        else:
                            if line[uri_index] not in uri_split_str_list_dict[str(len(line[uri_index].split('/')))][str(len(line[uri_index]))]:
                                uri_split_str_list_dict[str(len(line[uri_index].split('/')))][str(len(line[uri_index]))].append(line[uri_index])
                elif line[protocol_index] == "mqtt" and line[topic_index]:
                    if str(len(line[topic_index].split('/'))) not in topic_split_str_list_dict:
                        topic_split_str_list_dict[str(len(line[topic_index].split('/')))] = {str(len(line[topic_index])): [line[topic_index]]}
                    else:
                        if str(len(line[topic_index])) not in topic_split_str_list_dict[str(len(line[topic_index].split('/')))]:
                            topic_split_str_list_dict[str(len(line[topic_index].split('/')))][str(len(line[topic_index]))] = [line[topic_index]]
                        else:
                            if line[topic_index] not in topic_split_str_list_dict[str(len(line[topic_index].split('/')))][str(len(line[topic_index]))]:
                                topic_split_str_list_dict[str(len(line[topic_index].split('/')))][str(len(line[topic_index]))].append(line[topic_index])
                else:
                    pass
    print(uri_split_str_list_dict)
    print(topic_split_str_list_dict)
    return 0


def sort_dict_by_key(dictionary):
    sorted_dict = dict(sorted(dictionary.items(), key=lambda x: x[0]))
    return sorted_dict


def check_if_string_is_id_class(string_under_check):
    pattern = r'^[a-zA-Z0-9-]{16,}$'
    match = re.match(pattern, string_under_check)
    if match:
        return True
    else:
        return False


def remove_http_stop_words(string_list, disabled_words_list):
    """
    ad-hoc operation: remove some http header features parsed by wireshark
    """
    for word in disabled_words_list:
        string_list = [string for string in string_list if word not in string]
    return string_list


if __name__ == "__main__":
    read_all_uri_and_get_pattern(["SAU1CWRU2_1698735028.csv", "SAU1CWRU2_1698735212.csv", "ADU1CWRD88:97:46:2C:9A:CE_1697782343.csv"])


