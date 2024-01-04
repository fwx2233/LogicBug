import os
import datetime
import shutil

LOG_FOLDER_ROOT = os.path.dirname(__file__)
LOG_FILE = LOG_FOLDER_ROOT + "/program.log"

# tips
LOG = "[LOG]"
ERROR = "[ERROR]"
DEBUG = "[DEBUG]"


def log_func(log_level, log_message, t_count=0):
    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    print(formatted_time, log_level, end=" ")
    for temp_index in range(t_count):
        print("\t", end="")
    print(log_message)

    with open(LOG_FILE, "a+") as f:
        f.write(formatted_time + " ")
        for temp_index in range(t_count):
            f.write("\t")
        f.write(log_level + " " + str(log_message))
        f.write('\n')


def write_dict_to_file(data: dict, file):
    for key, value in data.items():
        if isinstance(value, dict):
            file.write(f"\t{key}:\n")
            write_dict_to_file(value, file)
        else:
            file.write(f"\t{key}: {value}\n")


def log_dict_func(log_level, log_dict: dict):
    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    print(formatted_time, log_level, "{")
    for (key, value) in log_dict.items():
        print('\t', key, ": ", value)
    print("}")

    with open(LOG_FILE, "a+") as f:
        f.write(formatted_time + " " + log_level + " {\n")
        write_dict_to_file(log_dict, f)
        f.write("}\n")


def clear_log():
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)


def save_log(log_name_new: str):
    shutil.move(LOG_FILE, LOG_FOLDER_ROOT + "/" + log_name_new)
