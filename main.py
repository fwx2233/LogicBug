"""
Main
"""
from learn_model import learn
from analyse_app import analyse


def start_main():
    print("[+] Program start")

    print("[+] Start analysing appcrawler result")
    analyse.analyse_main()

    print("[+] Start learn model")
    learn.learn_main()


if __name__ == "__main__":
    start_main()
