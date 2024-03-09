import subprocess, signal
import os

admin_password = "admin"
ROOT_PATH = os.path.dirname(__file__)


def kill_tshark():
    fine_name = ROOT_PATH + "/temp_tshark_ps"
    command = "ps aux|grep tshark > " + fine_name
    os.system(command)

    if os.path.exists(fine_name):
        with open(fine_name, "r") as f:
            lines = f.readlines()
        if len(lines) > 1:
            admin_proc = subprocess.Popen(["echo", admin_password], stdout=subprocess.PIPE)
            for lin in lines[:-2]:
                porc_id = lin.split()[1]
                command = "sudo -S kill -9 " + porc_id
                temp_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout)
            admin_proc.kill()
        os.remove(fine_name)


def kill_appium():
    fine_name = ROOT_PATH + "/temp_appium_ps"
    command = "ps aux|grep appium > " + fine_name
    os.system(command)

    if os.path.exists(fine_name):
        with open(fine_name, "r") as f:
            lines = f.readlines()
        if len(lines) > 1:
            admin_proc = subprocess.Popen(["echo", admin_password], stdout=subprocess.PIPE)

            for lin in lines[:-2]:
                porc_id = lin.split()[1]
                command = "sudo -S kill -9 " + porc_id
                temp_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout)
            admin_proc.kill()

        os.remove(fine_name)


def kill_mitm():
    admin_proc = subprocess.Popen(["echo", admin_password], stdout=subprocess.PIPE)
    # get process id
    file_name = ROOT_PATH + "/1.txt"
    command = "sudo -S netstat -tunlp|grep 8080 > " + file_name
    # save_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout, stdout=subprocess.PIPE)
    os.system('echo %s | sudo -S %s' % (admin_password, command))

    # parse id and kill mitm process
    if os.path.exists(file_name):
        with open(file_name, "r") as f:
            lines = f.readlines()
            if lines:
                process_id = lines[0].split()[-1].split("/")[0]
                command = "sudo -S kill -9 " + process_id
                # temp_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout)
                os.system('echo %s | sudo -S %s' % (admin_password, command))
        os.remove(file_name)
    # clear iptables

    command = "sudo -S bash " + ROOT_PATH + "/clear_iptables.bash"
    os.system('echo %s | sudo -S %s' % (admin_password, command))

    admin_proc.kill()


def kill_frida():
    fine_name = ROOT_PATH + "/temp_appium_ps"
    command = "ps aux|grep frida > " + fine_name
    os.system(command)

    if os.path.exists(fine_name):
        with open(fine_name, "r") as f:
            lines = f.readlines()
        if len(lines) > 1:
            admin_proc = subprocess.Popen(["echo", admin_password], stdout=subprocess.PIPE)

            for lin in lines[:-1]:
                porc_id = lin.split()[1]
                command = "sudo -S kill -9 " + porc_id
                temp_proc = subprocess.Popen(command.split(), stdin=admin_proc.stdout)
            admin_proc.kill()

        os.remove(fine_name)


# stop tshark and chmod
kill_tshark()
kill_appium()
# kill_mitm()
kill_frida()
