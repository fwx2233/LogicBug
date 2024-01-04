import Levenshtein
from collections import defaultdict


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


def use_total_important_word_for_classifying(op_name, pcap_payload_list):
    """
    get abstract class for each pcapng file by important packet and its payload(after removed word which has high entropy and some fields such as time or timestamp)
    :param op_name: operation name
    :param pcap_payload_list: payload of each pcap file, [[pcapng1:[payload1 for packet1, payload2 for packet1], [payload1 for packet2]],
                                                          [pcapng2:[payload1 for packet1, payload2 for packet1], [payload1 for packet2]]
    :return: class result list: [pcapng1_class, pcapng2_class]
    """
    print_entropy_list = []

    for pcapng_index in range(len(pcap_payload_list)):
        for payload_list_index in range(len(pcap_payload_list[pcapng_index])):
            pcap_payload_list[pcapng_index][payload_list_index] = "".join(pcap_payload_list[pcapng_index][payload_list_index])
        pcap_payload_list[pcapng_index] = "".join(pcap_payload_list[pcapng_index])

    temp_class_number = 0
    vector_mapping = {}
    for class_index_x in range(len(pcap_payload_list)):
        print_entropy_list.append([])
        for i in range(len(print_entropy_list) - 1):
            print_entropy_list[-1].append(-1)
        if class_index_x in vector_mapping.keys():
            print_entropy_list[-1].append(0.0)
            for i in range(len(pcap_payload_list) - len(print_entropy_list)):
                print_entropy_list[-1].append(-1)
            continue
        class_name = op_name + "_class_" + str(temp_class_number)
        temp_class_number += 1
        
        for class_index_y in range(class_index_x, len(pcap_payload_list)):
            if class_index_y in vector_mapping.keys():
                continue
            entropy = calculate_entropy([pcap_payload_list[class_index_x], pcap_payload_list[class_index_y]])
            print_entropy_list[-1].append(entropy)

            if entropy == 0:
                vector_mapping[class_index_y] = class_name

    vector_mapping = dict(sorted(vector_mapping.items(), key=lambda x: x[0]))
    return [value for number, value in vector_mapping.items()]
