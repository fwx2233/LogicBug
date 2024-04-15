import csv
import re
import os
from datetime import datetime, timezone, timedelta
from log import mlog
import socket
import sys

sys.setrecursionlimit(3000)


"""
tools of http header
"""


def remove_string_by_some_pattern(input_string):
    """
    Use regular expression to match string and modify the substring to abstract string if matching
    :param input_string: string under matching
    :return : string after modified
    """
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
    """
    Use it to keep uri(before "?")
    :param header_str: http uri, such as /a/b/c?d=4
    :return : uri before "?", such as /a/b/c
    """
    # keep the part before the "?"
    header_str = header_str.split("?")[0]
    return header_str


"""
sort tools
"""


def sort_dict_by_key(dictionary):
    sorted_dict = dict(sorted(dictionary.items(), key=lambda x: x[0]))
    return sorted_dict


def sort_dict_by_value(dictionary):
    sorted_dict = dict(sorted(dictionary.items(), key=lambda x: x[1]))
    return sorted_dict


"""
wireshark tools
"""


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
    start_timestamp = float(start_timestamp)
    end_timestamp = float(end_timestamp)

    if end_timestamp < start_timestamp:
        mlog.log_func(mlog.ERROR, "Please check your input, end_timestamp should be larger than or equal to start_timestamp")
        mlog.log_func(mlog.ERROR, f"Your input: start_timestamp={start_timestamp}, end_timestamp={end_timestamp}")
        return None
    start_format_time = transform_timestamp_to_datatime(start_timestamp)
    end_format_time = transform_timestamp_to_datatime(end_timestamp)
    wireshark_filter = f'(frame.time >= "{start_format_time}" && frame.time <= "{end_format_time}")'
    return wireshark_filter


def get_wireshark_filter_expression_by_blackname_list_dict(blackname_dict):
    """

    """
    domain_filter_condition = []
    for domains in blackname_dict["domain"]:
        domain_filter_condition.append('!(ip.host == "' + domains + '")')
    domain_filter_condition = " and ".join(domain_filter_condition)

    ip_filter_condition = []
    for ip in blackname_dict["ip"]:
        ip_filter_condition.append('!(ip.addr == ' + ip + ')')
    ip_filter_condition = " and ".join(ip_filter_condition)

    result_condition = []
    if domain_filter_condition:
        result_condition.append(domain_filter_condition)
    if ip_filter_condition:
        result_condition.append(ip_filter_condition)
    result_condition = " and ".join(result_condition)
    result_condition = "(" + result_condition + ")"
    return result_condition


def get_domain_by_ip(ip, domain_mapping_list):
    """
    Mapping ip to domain. First, check if there is a domain name cache in DNS. If not, use socket to obtain the host. If both are unavailable, return the IP.
    :param ip: IP
    :param domain_mapping_list: DNS mapping
    :return: domain or ip
    """
    if type(domain_mapping_list) == list:
        for mapping_item in domain_mapping_list:
            if ip in mapping_item:
                return mapping_item[ip]
        return ip
    if type(domain_mapping_list) == dict:
        if ip in domain_mapping_list:
            return domain_mapping_list[ip]
        return ip
    mlog.log_func(mlog.ERROR, "dns mapping type error(not list and not dict)")
    exit(-3)


def generate_selected_expression_by_ip_list(ip_list):
    """
    Use ip from ip_list to generate filter expression
    :param ip_list: selected ip
    :return : expression of wireshark
    """
    return_expression = "("
    for index in range(len(ip_list)):
        ip = ip_list[index]
        return_expression += f"ip.addr == {ip}"
        if index == len(ip_list) - 1:
            break
        return_expression += " or "
    return_expression += ")"

    return return_expression


"""
Template extraction based on randomness assessment
"""


def get_suffix_by_prefix(cur_prefix, separator_list, value_list, pattern_list):
    def get_value_fp_list(cur_prefix, value_list):
        """
        get next value_fp_list for current prefix
        """
        if int(len(cur_prefix) / 2) < len(value_list):
            return value_list[int(len(cur_prefix) / 2)]
        else:
            return []

    def get_value_pattern(value_fp_list, threshold=0.5):
        if len(value_fp_list) > 2 and len(set(value_fp_list)) / len(value_fp_list) >= threshold:
            return ["Abs_Len" + str(len(value_fp_list[0])) + "|"]
        elif len(value_fp_list) == 2 and value_fp_list[0] != value_fp_list[1]: # len(set(value_fp_list)) / len(value_fp_list) > 0.5:
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
                return separator_list[int(len(cur_prefix) / 2)]
            else:
                return ""

    # main
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

    cases = list(set(cases))

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


def get_unreadable_payload_pattern(cases):
    # get readable char list
    is_readable_char_list = [1] * len(cases[0].split(":"))

    for index in range(len(is_readable_char_list)):
        for item in cases:
            if not ("7E" >= item.split(":")[index] >= "20"):
                is_readable_char_list[index] = 0
                break

    zero_count = 0
    one_count = 0
    udp_payload_pattern_by_readable_list = []
    for index in range(len(is_readable_char_list)):
        if is_readable_char_list[index]:
            if zero_count:
                udp_payload_pattern_by_readable_list.append("Abs_Len" + str(zero_count) + "|")
                zero_count = 0
            one_count += 1
        else:
            if one_count:
                udp_payload_pattern_by_readable_list.append(one_count)
                one_count = 0
            zero_count += 1
    if zero_count:
        udp_payload_pattern_by_readable_list.append("Abs_Len" + str(zero_count) + "|")
    if one_count:
        udp_payload_pattern_by_readable_list.append(one_count)

    # convert byte to text
    for case_index in range(len(cases)):
        case_split = cases[case_index].split(":")
        temp_case = []
        readable_item_index = 0
        case_split_index = 0
        while readable_item_index < len(udp_payload_pattern_by_readable_list):
            if type(udp_payload_pattern_by_readable_list[readable_item_index]) == int:
                temp_str = ""
                for count_index in range(udp_payload_pattern_by_readable_list[readable_item_index]):
                    temp_str += chr(int(case_split[case_split_index + count_index], 16))
                case_split_index = case_split_index + udp_payload_pattern_by_readable_list[readable_item_index]
                temp_case.append(temp_str)
            else:
                t_count = int(udp_payload_pattern_by_readable_list[readable_item_index][7:-1])
                # case_split_index += (t_count + 1)
                case_split_index += t_count
                temp_case.append(udp_payload_pattern_by_readable_list[readable_item_index])

            readable_item_index += 1

        cases[case_index] = "".join(temp_case)

    temp_patterns = get_patterns_for_cases(cases)

    for pattern_index in range(len(temp_patterns)):
        temp_after_process_pattern = []
        for pat_item in temp_patterns[pattern_index]:
            if pat_item:
                temp_after_process_pattern.extend(split_feature_str_to_pattern_list(pat_item))

        # merge
        merged_pattern = []
        while temp_after_process_pattern:
            cur_item = temp_after_process_pattern.pop(0)
            if "Abs_Len" not in cur_item:
                merged_pattern.append(cur_item)
            else:
                new_len = int(cur_item[len("Abs_Len"):-1])
                while temp_after_process_pattern and "Abs_Len" in temp_after_process_pattern[0]:
                    new_len += int(temp_after_process_pattern.pop(0)[len("Abs_Len"):-1])
                merged_pattern.append(f"Abs_Len{new_len}|")

        temp_patterns[pattern_index] = merged_pattern

    # print(temp_patterns)
    return temp_patterns


def get_patterns_for_feature_payload_list(payload_list_for_cur_feature: list, is_hex=False):
    """

    :param payload_list_for_cur_feature:
    :return :
    """
    pattern_list = []
    for each_len_payload_list in payload_list_for_cur_feature:
        if not is_hex:
            pattern_list.append(get_patterns_for_cases(each_len_payload_list))
        else:
            pattern_list.append(get_unreadable_payload_pattern(each_len_payload_list))

    return pattern_list


"""
    Use pattern to match
"""


def get_regular_expression_from_pattern(pattern_split: list):
    """

    :param pattern_split: Split pattern list, such as
                ["{\"header\":{\"notifyType\":\"deviceDeleted\",\"category\":\"device\",\"timestamp\":\"|--------------|\"},\"body\":{\"devId\":\"",
                "Abs_Len8|",
                "-",
                "Abs_Len4|",
                "-4"]
    :return : regular expression
    """
    regular_expression = ""
    for unit in pattern_split:
        if "Abs_Len" not in unit:
            regular_expression += re.escape(unit)
        else:
            if "|" in unit:
                unit = unit.replace("|", "")
            abs_len = unit.split("Abs_Len")[-1]
            regular_expression += ".{" + abs_len + "}"  # get regular expression
    return regular_expression


def pattern_matching(case, patterns, is_hex=False):
    """
    Use patterns to match case. If matching, return pattern. If not, return None
    :param case: case under matching
    :param patterns: patterns
    :param is_hex: If case is hex data, check whether hex string is printable charactor
    :return : If matching, return pattern, else, return None
    """
    if is_hex:
        raw_case = case
        try:
            case_split = case.split(":")
            case_str = ""
            for index in range(len(case_split)):
                if "7E" >= case_split[index] >= "20":
                    case_str += chr(int(case_split[index], 16))
                else:
                    case_str += "8"
            case = case_str
        except ValueError:
            mlog.log_func(mlog.ERROR, f"ValueError in format_tools.py--pattern_matching(), current case: {raw_case}\n\tcurrent patterns: {patterns}")

    for pattern in patterns:
        pattern_str = get_regular_expression_from_pattern(pattern)
        if pattern_str == "payload_is_None" and (not case or case == pattern_str):
            return pattern
        if re.match(pattern_str, case):  # re.match? sure?
            return pattern

    return None


def get_pattern_index_in_pattern_list(pattern, pattern_list):
    try:
        current_pattern_str = "".join(pattern)
        for pattern_index in range(len(pattern_list)):
            if current_pattern_str == "".join(pattern_list[pattern_index]):
                return pattern_index
        return -1
    except TypeError:
        mlog.log_func(mlog.ERROR, f"TypeError, bad pattern: {pattern}")
        return -1


def split_feature_str_to_pattern_list(feature_str, abs_re = r"Abs_Len\d{1,}\|"):
    """

    :param feature_str:
    :return :
    """
    match = re.search(abs_re, feature_str)
    temp_list = []
    while match:
        if match.span()[0] > 0:
            temp_list.append(feature_str[:match.span()[0]])
        temp_list.append(feature_str[match.span()[0]: match.span()[1]])

        # update
        feature_str = feature_str[match.span()[1]:]
        match = re.search(abs_re, feature_str)
    if feature_str:
        temp_list.append(feature_str)

    return temp_list


def get_feature_pattern_str(header_feature_str, patterns):
    match_pattern = pattern_matching(header_feature_str, patterns)
    return "".join(patterns[get_pattern_index_in_pattern_list(match_pattern, patterns)])


if __name__ == "__main__":
    # read payload patterns from database
    test_list = ['00:af:52:02:1e:fc:b4:2e:73:79:73:05:6c:6f:67:69:6e:e4:06:ed:6e:1e:7c:6b:ff:b8:9c:67:a8:79:9d:0b:75:7c:46:fc:af:f6:3b:96:c5:9f:cf:83:a9:1d:89:0f:39:05:81:ef:22:cf:c9:6a:28:15:1e:ef:d5:3e:e1:81:df:e1:81:14:2b:d2:f8:86:7d:ab:ae:a3:ce:4c:d7:0f:fd:ac:60:38:27:bd:bf:87:d3:ff:aa:fb:c0:a1:8f:53:8f:3f:df:ee:da:20:f2:7f:8b:c3:d2:a4:d7:1b:81:04:11:20:41:c9:71:3c:4e:79:bf:dd:24:81:ef:eb:8d:6b:ff:0c:4a:ca:f6:68:8c:13:e0:67:86:67:bd:16:12:6f:75:50:ac:74:0a:2b:49:c4:a0:ab:9e:2c:4b:d9:6a:b3:e0:87:de:79:b2:b4:47:31:cf:5d:6a:0a:62:e8:e8:9f:4d', '00:af:52:02:3d:1c:b4:2e:73:79:73:05:6c:6f:67:69:6e:e4:06:ed:2b:9f:e4:bd:ff:61:52:5b:3b:5e:b2:bd:b3:9c:52:db:fa:b9:0c:34:9e:1c:35:64:85:fe:c8:4e:c5:82:5e:b4:96:2f:59:fd:83:e6:23:b7:7f:08:4d:57:5b:15:8c:9a:4b:40:69:01:e4:f0:21:11:c8:2f:6f:35:17:55:b1:aa:cb:f7:59:30:d8:9a:81:74:4e:28:59:0e:0b:f0:21:2a:15:6b:b8:c2:bb:04:33:48:bc:1a:28:7b:a6:37:46:07:13:f9:30:e7:a8:98:90:4b:a2:02:cd:69:21:85:f0:60:9d:d6:cd:d8:94:13:79:c4:a6:f5:89:06:a9:71:5c:4e:43:6c:c7:15:55:1f:5d:79:c8:f2:03:17:dc:f6:7d:a0:0b:06:43:5a:a8:a7:ac:07:2a:38:ac:b0:45', '00:af:52:02:d2:ad:b4:2e:73:79:73:05:6c:6f:67:69:6e:e4:06:ed:7b:10:95:cb:ff:9f:a7:16:d2:80:55:b4:47:2d:c6:c0:70:26:a0:30:a0:e3:70:60:84:f9:14:5a:33:d3:a3:60:08:f2:25:fc:61:1f:f0:89:3f:b8:6a:08:8c:76:99:e5:93:c9:33:12:68:eb:6d:6d:ff:6a:e9:d9:30:35:9a:7d:70:76:41:d7:e0:22:94:1c:b9:01:d0:c8:5a:2e:45:a4:1d:8d:46:62:cc:35:4d:c4:76:d8:04:9e:29:e2:68:f4:6a:ca:0a:89:8c:29:70:72:83:cd:f2:43:0f:22:93:83:38:6e:6b:6d:e9:80:1c:f7:3b:ad:91:d6:d7:fa:fe:6d:b5:5c:3d:12:af:fd:ac:e5:7b:6a:68:68:c9:84:04:7c:52:12:ed:8a:e4:02:27:8c:a6:8c:db:9c:4d']
    print(get_unreadable_payload_pattern(test_list))
