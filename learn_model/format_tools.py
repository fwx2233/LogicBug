import re


def filter_some_strings_by_re(string):
    patterns = [r'"*\b(time|date|timestamp)\b"*:*',
                r'\d{1,2} \w{3} \d{4} \d{2}:\d{2}:\d{2} \w{3}',
                r'[a-zA-Z0-9]*time[a-zA-Z0-9]*',
                r'"*\b(seq)\b"*:*']
    for pattern in patterns:
        if re.search(pattern, string, re.IGNORECASE):
            return True
    return False


def remove_string_by_some_pattern(strings):
    for reverse_index in range(len(strings) - 1, -1, -1):
        if filter_some_strings_by_re(strings[reverse_index]):
            # strings.pop(reverse_index)
            strings[reverse_index] = "--pattern-string--"
    return strings


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


if __name__ == "__main__":
    json_str = '{"hasMore": false, "customerDatas": [{"value": {"updateCloudTimeStamp": 1698735702739, "deviceseq": [{"id": "30df5e4f-1e53-490e-ba24-dc8366b9c99e", "newdev": 0, "node": [], "seq": 0}], "savefrom": "android"}, "key": "devicecardseq-2nsepriccd01fdvnm8m3ieg", "name": "devicecardseq-2nsepriccd01fdvnm8m3ieg", "Time": 1698735702739", time: ddddd,  20 Oct 2023 06:12:08 GMT, "createTime": "2023-10-20 20:52:56", endTime: 11-22-2023}]}'
    json_str = remove_split_characters(json_str)
    print(json_str.split(","))
    print(",".join(remove_string_by_some_pattern(json_str.split(","))))
