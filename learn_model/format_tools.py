import re


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


def format_uri_header_features(uri_str):
    replacements = {"/": " ",
                    ".": " ",
                    "?": " ",
                    "&": " ",
                    "=": " "}
    for old_str, new_str in replacements.items():
        uri_str = uri_str.replace(old_str, new_str)

    return uri_str


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
