import os
import subprocess

from log import mlog
from config.device_appium_config import device_configs


class MitmCLs:
    def __init__(self, identity):
        # path of folders
        self.ROOT_PATH = os.path.dirname(__file__)
        self.LOG_FOLDER_PATH = self.ROOT_PATH + "/../log/"
        self.PACKET_ROOT_PATH = self.ROOT_PATH + "/packets/"
        self.CONF_FOLDER_PATH = self.ROOT_PATH + "/../config/"
        self.SCRIPTS_FOLDER = self.ROOT_PATH + "/../scripts/"

        # other
        self._admin_password = "admin"
        self._identity_phone_dict = {}
        for phone, values in device_configs.items():
            self._identity_phone_dict[values["additionalMess"]["identity"]] = phone
        if identity not in self._identity_phone_dict.keys():
            mlog.log_func(mlog.ERROR, f"Wrong identity, please select in {list(self._identity_phone_dict.keys())}")
            exit(-1)
        self.identity = identity.lower()

    # def _modify_mitm_script(self):
    #     mlog.log_func(mlog.LOG, "Modify mitm script")
    #     self.cur_key_log_file_path = self.PACKET_ROOT_PATH + 'sslkeylogfile.txt'
    #
    #     # modify script
    #     lines = []
    #     with open(self.SCRIPTS_FOLDER + "launch_mitm.bash", "r") as f:
    #         for line in f.readlines():
    #             lines.append(line)
    #     # lines[1] = 'WIRELESS_CARD="' + self.WIRELESS_CARD + '"\n'
    #     lines[2] = 'KEY_LOG_FILE="' + self.PACKET_ROOT_PATH + 'sslkeylogfile.txt"\n'
    #     with open(self.SCRIPTS_FOLDER + "launch_mitm.bash", "w") as f:
    #         for line in lines:
    #             f.write(line)
    #     lines.clear()  # clear
    #
    #     lines = []
    #     with open(self.SCRIPTS_FOLDER + "change_iptables.bash", "r") as f:
    #         for line in f.readlines():
    #             lines.append(line)
    #     lines[1] = 'WIRELESS_CARD="' + self.WIRELESS_CARD + '"\n'
    #     with open(self.SCRIPTS_FOLDER + "change_iptables.bash", "w") as f:
    #         for line in lines:
    #             f.write(line)

    def _change_ip_tables(self):
        """
        enable forward and change ip tables forward rules
        """
        mlog.log_func(mlog.LOG, f"Change <{self.identity}> iptable rules")
        command = f"bash {self.SCRIPTS_FOLDER}/change_iptables_{self.identity}.bash"
        os.system('echo %s | sudo -S %s' % (self._admin_password, command))

    def clear_ip_tables(self):
        """
        clear ip tables forward rules
        """
        mlog.log_func(mlog.LOG, "Clear iptable rules")
        command = f"bash {self.SCRIPTS_FOLDER}/clear_iptables.bash"
        os.system('echo %s | sudo -S %s' % (self._admin_password, command))

    def _launch_mitm(self):
        """
        start mitmproxy
        """
        mlog.log_func(mlog.LOG, f"Start mitmproxy --- {self.identity}")
        cur_log_file = f"{self.LOG_FOLDER_PATH}/mitm_{self.identity}.log"
        cur_script_file = f"{self.SCRIPTS_FOLDER}launch_mitm_{self.identity}.bash"
        # clear the log file
        with open(cur_log_file, "w") as file:
            pass
        mitm_proc = subprocess.Popen(["bash", cur_script_file], stdout=open(cur_log_file, "w"))

    def start_mitm_main(self):
        """
        start mitmproxy
        """
        self._change_ip_tables()
        self._launch_mitm()

    def stop_mitm_process(self):
        """
        Use kill -9 and port to kill mitm process
        """
        mlog.log_func(mlog.LOG, "Kill mitm process")

        admin_proc = subprocess.Popen(["echo", self._admin_password], stdout=subprocess.PIPE)
        # get process id
        file_name = self.LOG_FOLDER_PATH + "kell_mitm.txt"
        port = "8080" if self.identity == "host" else "8081"
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

        if os.path.exists(f"{self.LOG_FOLDER_PATH}/mitm_{self.identity}.log"):
            os.remove(f"{self.LOG_FOLDER_PATH}/mitm_{self.identity}.log")

    def stop_mitm_and_clear_iptables(self):
        self.stop_mitm_process()
        self.clear_ip_tables()


if __name__ == "__main__":
    host_mitm_entity = MitmCLs("host")

