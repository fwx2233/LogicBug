import os
import shutil
import subprocess
import time

from log import mlog
from config.device_appium_config import phone_configs, appium_path


class MitmCLs:
    def __init__(self, distance):
        # path of folders
        self.ROOT_PATH = os.path.dirname(__file__)
        self.LOG_FOLDER_PATH = self.ROOT_PATH + "/../log/"
        self.PACKET_ROOT_PATH = self.ROOT_PATH + "/packets/"
        self.CONF_FOLDER_PATH = self.ROOT_PATH + "/../config/"
        self.SCRIPTS_FOLDER = self.ROOT_PATH + "/../scripts/"

        # other
        self._admin_password = "admin"
        self._distance_phone_dict = {}
        for phone, values in phone_configs.items():
            self._distance_phone_dict[values["additionalMess"]["distance"]] = phone
        if distance not in self._distance_phone_dict.keys():
            mlog.log_func(mlog.ERROR, f"Wrong distance, please select in {list(self._distance_phone_dict.keys())}")
            exit(-1)
        self.distance = distance.lower()
        self._WIRELESS_CARD = phone_configs[self._distance_phone_dict[self.distance]]["additionalMess"]["wirelessCard"]

        # write scripts
        self._write_change_ip_tables_script()
        self._write_clear_ip_tables_script()
        self._write_launch_mitm_script("/usr/local/python/python3.8/bin/mitmdump")
        self._write_set_forward_script()

    """
    iptables and mitmproxy
    """
    def _write_set_forward_script(self):
        with open(self.SCRIPTS_FOLDER + "set_net_forward.bash", "w") as sc_file:
            sc_file.write("sudo sysctl -w net.ipv4.ip_forward=1\nsudo sysctl -w net.ipv4.conf.all.send_redirects=0\n")

    def _set_forward(self):
        """
        enable forward and change ip tables forward rules
        """
        mlog.log_func(mlog.LOG, f"Set forward")
        command = f"bash {self.SCRIPTS_FOLDER}/set_net_forward.bash"
        os.system('echo %s | sudo -S %s' % (self._admin_password, command))

    def _write_change_ip_tables_script(self):
        dst_port = "8080" if self.distance == "local" else "8081"
        with open(self.SCRIPTS_FOLDER + "change_iptables_" + self.distance + ".bash", "w") as sc_file:
            sc_file.write("#!/bin/bash\n")
            sc_file.write(f'WIRELESS_CARD="{self._WIRELESS_CARD}"\n\n')
            sc_file.write(f"# set redirect port(MQTT: 8883, HTTP: 80, HTTS: 443)\nsudo iptables -t nat -A PREROUTING -i $WIRELESS_CARD -p tcp --dport 80 -j REDIRECT --to-port {dst_port}\nsudo iptables -t nat -A PREROUTING -i $WIRELESS_CARD -p tcp --dport 443 -j REDIRECT --to-port {dst_port}\nsudo iptables -t nat -A PREROUTING -i $WIRELESS_CARD -p tcp --dport 8883 -j REDIRECT --to-port {dst_port}")

    def _change_ip_tables(self):
        """
        enable forward and change ip tables forward rules
        """
        mlog.log_func(mlog.LOG, f"Change <{self.distance}> iptable rules")
        command = f"bash {self.SCRIPTS_FOLDER}/change_iptables_{self.distance}.bash"
        os.system('echo %s | sudo -S %s' % (self._admin_password, command))

    def _write_clear_ip_tables_script(self):
        with open(f"{self.SCRIPTS_FOLDER}/clear_iptables.bash", "w") as sc_file:
            sc_file.write("# set iptables rules\nsudo iptables -F PREROUTING -t nat")

    def clear_ip_tables(self):
        """
        clear ip tables forward rules
        """
        mlog.log_func(mlog.LOG, "Clear iptable rules")
        command = f"bash {self.SCRIPTS_FOLDER}/clear_iptables.bash"
        os.system('echo %s | sudo -S %s' % (self._admin_password, command))

    def _write_launch_mitm_script(self, mitm_path):
        dst_port = "8080" if self.distance == "local" else "8081"
        with open(f"{self.SCRIPTS_FOLDER}/launch_mitm_{self.distance}.bash", "w") as sc_file:
            sc_file.write('#!/bin/bash\n')
            sc_file.write(f'KEY_LOG_FILE="{self.PACKET_ROOT_PATH}/sslkeylogfile_{self.distance}.txt"\n\n')
            sc_file.write("# delete current key log file and create a new one\nrm $KEY_LOG_FILE\ntouch $KEY_LOG_FILE\n\n")
            sc_file.write(f'# launch mitmproxy on transparent mode\nSSLKEYLOGFILE="$KEY_LOG_FILE" {mitm_path} --mode transparent -v --ssl-insecure --tcp-host \'.*\' -p {dst_port}')

    def _launch_mitm(self):
        """
        start mitmproxy
        """
        mlog.log_func(mlog.LOG, f"Start mitmproxy --- {self.distance}")
        cur_log_file = f"{self.LOG_FOLDER_PATH}/mitm_{self.distance}.log"
        cur_script_file = f"{self.SCRIPTS_FOLDER}launch_mitm_{self.distance}.bash"
        # clear the log file
        with open(cur_log_file, "w") as file:
            pass
        mitm_proc = subprocess.Popen(["bash", cur_script_file], stdout=open(cur_log_file, "w"))

    def start_mitm_main(self, change_flag=True):
        """
        start mitmproxy
        """
        if change_flag:
            self._set_forward()
        self._change_ip_tables()
        self._launch_mitm()

    def _stop_mitm_process(self, save_keylog_file_path=None):
        """
        Use kill -9 and port to kill mitm process
        """
        mlog.log_func(mlog.LOG, "Kill mitm process")

        admin_proc = subprocess.Popen(["echo", self._admin_password], stdout=subprocess.PIPE)
        # get process id
        file_name = self.LOG_FOLDER_PATH + "kell_mitm.txt"
        port = "8080" if self.distance == "local" else "8081"
        command = f"netstat -tunlp|grep {port} > {file_name}"
        # save_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout, stdout=subprocess.PIPE)
        os.system('echo %s | sudo -S %s' % (self._admin_password, command))

        # parse id and kill mitm process
        if os.path.exists(file_name):
            with open(file_name, "r") as f:
                lines = f.readlines()
                if lines:
                    process_id = lines[0].split()[-1].split("/")[0]
                    command = "kill -9 " + process_id
                    os.system('echo %s | sudo -S %s' % (self._admin_password, command))
            os.remove(file_name)

        admin_proc.kill()

        if os.path.exists(f"{self.LOG_FOLDER_PATH}/mitm_{self.distance}.log"):
            os.remove(f"{self.LOG_FOLDER_PATH}/mitm_{self.distance}.log")

        # save key log file
        if save_keylog_file_path and os.path.exists(f"{self.PACKET_ROOT_PATH}/sslkeylogfile_{self.distance}.txt"):
            shutil.move(f"{self.PACKET_ROOT_PATH}/sslkeylogfile_{self.distance}.txt", save_keylog_file_path)

    def stop_mitm_and_clear_iptables(self, save_keylog_file_path=None):
        self._stop_mitm_process(save_keylog_file_path)
        self.clear_ip_tables()

    """
    tshark
    """
    def start_tshark(self, pcapng_name):
        # admin_proc
        admin_proc = subprocess.Popen(["echo", self._admin_password], stdout=subprocess.PIPE)

        cur_packet_name = pcapng_name + '_' + str(int(time.time())) + ".pcapng"

        # create folder
        cur_packet_folder = self.PACKET_ROOT_PATH + cur_packet_name[:-7] + "/"
        if not os.path.exists(cur_packet_folder):
            os.makedirs(cur_packet_folder)

        cur_packet_path = cur_packet_folder + cur_packet_name

        mlog.log_func(mlog.LOG, "Start capturing, save in file: " + self.PACKET_ROOT_PATH + cur_packet_name)
        with open(self.LOG_FOLDER_PATH + "tshark_log_file.txt", "w") as log_file:
            pass
        a = subprocess.Popen(["tshark", "-i", self._WIRELESS_CARD, "-w", cur_packet_path], stdout=open(self.LOG_FOLDER_PATH + "tshark_log_file.txt", "w"))

        admin_proc.kill()

        return cur_packet_name

    def stop_tshark(self):
        mlog.log_func(mlog.LOG, "kill tshark")

        fine_name = self.SCRIPTS_FOLDER + "temp_tshark_ps"
        command = "ps -aux|grep tshark > " + fine_name
        os.system(command)

        with open(fine_name, "r") as f:
            lines = f.readlines()
        if len(lines) > 1:
            # admin_proc = subprocess.Popen(["echo", self.admin_password], stdout=subprocess.PIPE)
            for lin in lines[:-2]:
                porc_id = lin.split()[1]
                command = "kill -9 " + porc_id
                # temp_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout)
                os.system('echo %s | sudo -S %s' % (self._admin_password, command))
            # admin_proc.kill()
        os.remove(fine_name)


if __name__ == "__main__":
    host_mitm_entity = MitmCLs("local")

