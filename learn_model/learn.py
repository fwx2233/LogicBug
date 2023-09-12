"""
Learn APP's model
"""
import os

ROOT_PATH = os.path.dirname(__file__)
PACKET_ROOT_PATH = ROOT_PATH + "./packets/"


def save_packet(packet, file_name):
    """
    Save the packet when the corresponding button is clicked for fuzzing.
    :param packet: The packet that is generated when the button is clicked.
    :param file_name:
    :return:
    """
    pass


def get_output(packet) -> str:
    """
    Get output from packet;
    :param packet: The packet that is generated when the button is clicked.
    :return: output
    """
    pass


def response_to_learner(output):
    """
    Tell the learner the output of operation.
    :param output:
    :return:
    """
    pass


def click_button(ui_name, uip_list):
    """
    Click the button and save packets
    :param ui_name:
    :param uip_list:
    :return:
    """
    pass

