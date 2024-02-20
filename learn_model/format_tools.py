import csv
import re
import os
from datetime import datetime, timezone, timedelta
from log import mlog
import socket
import sys

sys.setrecursionlimit(3000)


def filter_some_strings_by_re(string):
    patterns = [r'\d{10}(?!\d)',
                r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
                r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3}',
                r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',
                r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z',
                r'\d{4}-\d{2}-\d{2}',
                r'\d{2}/\d{2}/\d{4}',
                r'\d{2}-\d{2}-\d{4}',
                r'\d{2}\.\d{2}\.\d{4}',
                r'\d{4}/\d{2}/\d{2}',
                r'\d{8}T\d{6,}Z'
                ]
    for pattern in patterns:
        if re.search(pattern, string, re.IGNORECASE):
            return True
    return False


def remove_string_by_some_pattern(input_string):
    def modify_by_pattern(pattern, string_under_modify):
        match = re.search(pattern, string_under_modify)
        if not match:
            return string_under_modify

        while match:
            replace_str = "|" + "-" * (len(match.group()) - 2) + "|"
            string_under_modify = string_under_modify.replace(match.group(), replace_str)
            match = re.search(pattern, string_under_modify)

        return string_under_modify

    YMD_STR = r"((([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3})([-/.]?)(((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8]))))|((([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))([-/.]?)02([-/.]?)29))"
    MDY_STR = r"(((((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8])))([-/.]?)([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3}))|(02([-/.]?)29([-/.]?)(([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))))"
    TIME_STR = r"([0-1]?[0-9]|2[0-3])[-:]?([0-5][0-9])[-:]?([0-5][0-9])"
    regex_patterns = [
        r"((([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3})([-/.]?)(((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8]))))|((([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))([-/.]?)02([-/.]?)29))\\s+([0-1]?[0-9]|2[0-3])[-:]?([0-5][0-9])[-:]?([0-5][0-9])(.?)\d{3}",  # \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3}
        r"((([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3})([-/.]?)(((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8]))))|((([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))([-/.]?)02([-/.]?)29))\\s+([0-1]?[0-9]|2[0-3])[-:]?([0-5][0-9])[-:]?([0-5][0-9])",  # \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}
        r"((([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3})([-/.]?)(((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8]))))|((([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))([-/.]?)02([-/.]?)29))T([0-1]?[0-9]|2[0-3])[-:]?([0-5][0-9])[-:]?([0-5][0-9])(.?)\d{3}Z",  # \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z
        r"((([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3})([-/.]?)(((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8]))))|((([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))([-/.]?)02([-/.]?)29))T([0-1]?[0-9]|2[0-3])[-:]?([0-5][0-9])[-:]?([0-5][0-9])Z",  # \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z
        r"(?<!\d)((([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3})([-/.]?)(((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8]))))|((([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))([-/.]?)02([-/.]?)29))(?!\d)",  # YYYY-/.MM-/.DD
        r"(?<!\d)(((((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8])))([-/.]?)([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3}))|(02([-/.]?)29([-/.]?)(([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))))(?!\d)",  # MM-/.DD-/.YYYY
        r"(?<!\d)([0-1]?[0-9]|2[0-3])[-:]([0-5][0-9])[-:]([0-5][0-9])(?!\d)",  # HH-:MM-:SS
        r'(?<!\d)(1|2)\d{9,12}(?!\d)',  # timestamp
    ]

    for pattern in regex_patterns:
        input_string = modify_by_pattern(pattern, input_string)

    return input_string


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


def simply_format_header_feature(header_str: str):
    # keep the part before the "?"
    header_str = header_str.split("?")[0]
    return header_str


# continue
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


"""
sort tools
"""
def sort_dict_by_key(dictionary):
    sorted_dict = dict(sorted(dictionary.items(), key=lambda x: x[0]))
    return sorted_dict


def sort_dict_by_value(dictionary):
    sorted_dict = dict(sorted(dictionary.items(), key=lambda x: x[1]))
    return sorted_dict


def transform_timestamp_to_datatime(timestamp, offset=8) -> str:
    """
    transform timestamp to datatime format, such as: 1697782138 ->
    :param timestamp: unix timestamp, such as 1697782138
    :param offset: Offset from UTC, for example: CST=UTC+8
    :return datatime: "YYYY-MM-DD HH:MM:SS.sss"
    """
    timestamp = float(timestamp)
    date_object = datetime.fromtimestamp(timestamp, timezone(timedelta(hours=offset)))
    formatted_time = date_object.strftime("%Y-%m-%d %H:%M:%S")
    return formatted_time


def get_wireshark_filter_by_timestamp(start_timestamp, end_timestamp):
    """
    Generate Wireshark filter expression using timestamp ranges.
    :param start_timestamp: start timestamp
    :param end_timestamp: end timestamp
    :return: wireshark filter expression or None(if the input is wrong)
    """
    # check if end_timestamp is larger than or equal to start_timestamp
    if end_timestamp < start_timestamp:
        mlog.log_func(mlog.ERROR, "Please check your input, end_timestamp should be larger than or equal to start_timestamp")
        mlog.log_func(mlog.ERROR, f"Your input: start_timestamp={start_timestamp}, end_timestamp={end_timestamp}")
        return None
    start_format_time = transform_timestamp_to_datatime(start_timestamp)
    end_format_time = transform_timestamp_to_datatime(end_timestamp)
    wireshark_filter = f'(frame.time >= "{start_format_time}" && frame.time <= "{end_format_time}")'
    return wireshark_filter


def get_domain_by_ip(ip, domain_mapping_list):
    """
    Mapping ip to domain. First, check if there is a domain name cache in DNS. If not, use socket to obtain the host. If both are unavailable, return the IP.
    :param ip: IP
    :param domain_mapping_list: DNS mapping
    :return: domain or ip
    """
    for mapping_item in domain_mapping_list:
        if ip in mapping_item:
            return mapping_item[ip]
    try:
        target_domain = socket.gethostbyaddr(ip)[0]
        return "compute." + target_domain.split("compute.")[-1]
    except socket.herror:
        return ip


"""
Template extraction based on randomness assessment
"""
def get_separators_and_values(same_len_input_list):
    """

    """
    # transform to string
    str_input_list = [str(x) for x in same_len_input_list]

    # check len
    check_len = len(str_input_list[0])
    for x in str_input_list:
        if len(x) != check_len:
            mlog.log_func(mlog.ERROR, "Please check your input: ensure that all content in the input is of the same length")
            mlog.log_list_func(mlog.ERROR, str_input_list)
            exit(111)

    # get separator list and value index information
    value_fp_index_list = []
    separator_list = []
    pattern_result = ""
    cur_value_fp = []
    for str_index in range(len(str_input_list[0])):
        cur_chr = str_input_list[0][str_index]
        break_flag = False
        for string in str_input_list[1:]:
            if string[str_index] != cur_chr:
                if str_index == 0 or pattern_result != "":
                    separator_list.append(pattern_result)
                    pattern_result = ""
                break_flag = True
                if len(cur_value_fp) == 0:
                    cur_value_fp.append(str_index)
                break
        if not break_flag:
            pattern_result += cur_chr
            if len(cur_value_fp) == 1:
                cur_value_fp.append(str_index)
                value_fp_index_list.append(cur_value_fp.copy())
                cur_value_fp.clear()

    # check if cur_value_fp has only one position
    if len(cur_value_fp) == 1:
        value_fp_index_list.append(cur_value_fp.copy())
    if pattern_result != "":
        separator_list.append(pattern_result)

    # get value list
    value_list = []
    for string_index_list in value_fp_index_list:
        temp_list = []
        for string in str_input_list:
            if len(string_index_list) == 2 and string_index_list[0] < string_index_list[1]:
                temp_list.append(string[string_index_list[0]:string_index_list[1]])
            else:
                temp_list.append(string[string_index_list[0]:])
        value_list.append(temp_list.copy())

    return separator_list, value_list


def get_value_fp_list(cur_prefix, value_list):
    """
    get next value_fp_list for current prefix
    """
    # for index in range(len(separator_list)):
    #     if separator_list[index] == "":
    #         continue
    #     if separator_list[index] not in cur_prefix:
    #         break
    #
    # if separator_list[0] == "":
    #     return value_list[index]
    # else:
    #     return value_list[index - 1]
    if int(len(cur_prefix)/2) < len(value_list):
        return value_list[int(len(cur_prefix) / 2)]
    else:
        return []


def get_value_pattern(value_fp_list, threshold=0.5):
    if len(value_fp_list) > 2 and len(set(value_fp_list)) / len(value_fp_list) >= threshold:
        return ["Abs_Len" + str(len(value_fp_list[0])) + "|"]
    elif len(value_fp_list) == 2 and len(set(value_fp_list)) / len(value_fp_list) > threshold:
        return ["Abs_Len" + str(len(value_fp_list[0])) + "|"]
    else:
        return list(set(value_fp_list))


def get_next_separator(cur_prefix, separator_list):
    if separator_list[0] == cur_prefix[0]:
        if int((len(cur_prefix) + 1) / 2) < len(separator_list):
            return separator_list[int((len(cur_prefix) + 1) / 2)]
        else:
            return ""
    else:
        if int(len(cur_prefix) / 2) < len(separator_list):
            return separator_list[int(len(cur_prefix)/2)]
        else:
            return ""


def get_suffix_by_prefix(cur_prefix, separator_list, value_list, pattern_list):
    value_fp_lit = get_value_fp_list(cur_prefix, value_list)

    if value_fp_lit:
        value_pattern_list = get_value_pattern(value_fp_lit)
        for value_pattern in value_pattern_list:
            next_prefix = cur_prefix.copy()
            next_prefix.append(value_pattern)
            next_prefix.append(get_next_separator(next_prefix, separator_list))

            # get value_list for current pattern
            if len(value_pattern_list) == 1:
                get_suffix_by_prefix(next_prefix, separator_list, value_list, pattern_list)
            else:
                next_value_index_list = []
                for index in range(len(value_fp_lit)):
                    if value_fp_lit[index] == value_pattern:
                        next_value_index_list.append(index)
                next_value_list = []
                for i in range(len(value_list)):
                    temp_value_col = []
                    for index in next_value_index_list:
                        temp_value_col.append(value_list[i][index])
                    next_value_list.append(temp_value_col.copy())
                get_suffix_by_prefix(next_prefix, separator_list, next_value_list.copy(), pattern_list)
    else:
        if cur_prefix:
            pattern_list.append(cur_prefix)
        return


def get_patterns_for_cases(cases):
    separator_list, value_list = get_separators_and_values(cases)
    init_prefix = [separator_list[0]]
    patterns = []
    get_suffix_by_prefix(init_prefix, separator_list, value_list, patterns)

    # merge
    for each_pattern_index in range(len(patterns)):
        merged_pattern = []
        temp_str = ""
        for pattern_i_index in range(len(patterns[each_pattern_index])):
            if "Abs_Len" in patterns[each_pattern_index][pattern_i_index]:
                merged_pattern.append(temp_str)
                merged_pattern.append(patterns[each_pattern_index][pattern_i_index])
                temp_str = ""
            else:
                temp_str += patterns[each_pattern_index][pattern_i_index]
        if temp_str != "":
            merged_pattern.append(temp_str)
        patterns[each_pattern_index] = merged_pattern.copy()

    return patterns


"""
    Use pattern to match
"""
def pattern_matching(case, patterns):
    """

    """
    for pattern in patterns:
        pattern_str = ""
        for unit in pattern:
            if "Abs_Len" not in unit:
                pattern_str += unit
            else:
                abs_len = unit.split("Abs_Len")[-1][:-1]
                pattern_str += ".{" + abs_len + "}"  # get regular expression
        if re.match(pattern_str, case):  # re.match? sure?
            return pattern

    return None


if __name__ == "__main__":
    input_string = "{\"header\":{\"notifyType\":\"deviceDataChanged\",\"requestId\":\"e6e82cf4-fa34-43f3-90e6-8ee9c6bf538c\",\"from\":\"data-manager\",\"to\":\"app\",\"category\":\"device\",\"timestamp\":\"20240219T080517Z\"},\"body\":{\"devId\":\"cd14156e-6371-4d5e-a380-194f86c72afb\",\"services\":[{\"st\":\"switch\",\"data\":{\"on\":1},\"sid\":\"switch\",\"ts\":\"20240219T080517150Z\"}],\"gatewayId\":\"cd14156e-6371-4d5e-a380-194f86c72afb\"}}"
    print(remove_string_by_some_pattern(input_string))
