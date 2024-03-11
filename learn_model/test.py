import json
import os
import socket

print("Start connecting to server...")

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

socket.bind(("", 7009))

socket.connect(("127.0.0.1", 9999))

print("Connection build")

with open(os.path.dirname(__file__) + "/../config/" + "valuable_button.json", "r") as val_but_file:
    but_dict = json.load(val_but_file)

overlook_list = ["user1|AS", "user1|SDU1CWR", "user1|VD1S", #"user1|ADU1CWR", "user1|RDU1CWR", "user1|DCU1",
                     "user2|AcceptDeviceShare", "user2|RejectDeviceShare", "user2|AcceptInvite", "user2|DenyInvite"]

ui_list = []
for user, button_dict in but_dict.items():
    button_name_list = list(button_dict.keys())
    for item in button_name_list:
        if item != "Special" and (user + "|" + item) not in overlook_list:
            ui_list.append(user + "|" + item)

message = socket.recv(1024)
message_type = message[0]
context = message[1:].decode('utf-8')
if message_type == 0 and context == "alphabet":
    print("Receive alphabet send request")

    # create file for alphabet
    alphabet_file = os.path.dirname(__file__) + "/learnlib_module/src/main/resources/input_bat"
    with open(alphabet_file, "w") as f:
        for item in ui_list:
            if item != ui_list[-1]:
                f.write(item + "\n")
            else:
                f.write(item)
    print("Create the alphabet file input_bat")

    # Send reply message
    reply_context = "Succeed!"
    reply_message = bytes([0]) + reply_context.encode('utf-8')
    socket.sendall(reply_message)
    print("Send alphabet success")
else:
    print("Don't receive alphabet send request")

while True:
    message = socket.recv(1024)
    message_type = message[0]
    context = message[1:].decode('utf-8')
    if message_type == 0:
        print("Receive system message: " + context)
    elif message_type == 1:
        print("Receive learnlib message: " + context)
    elif message_type == 2:
        print("Receive query message: " + context)
    else:
        print("Don't receive input message")

    option = context

    if option == "closeConnect":
        print("Stop learning...")
        reply_message = bytes([1]) + "close the client".encode('utf-8')
        print("Send reply message: " + "close the client")
        socket.sendall(reply_message)
        print("Close the socket...")
        socket.close()
        break

    if option == "checkCounterExample":
        print("Check the counter example...")
        reply_message = bytes([1]) + "WaitForChecking".encode('utf-8')
        print("Send reply message: " + "WaitForChecking")
        socket.sendall(reply_message)
        continue

    if option == "Reset":
        print("Reset")
        reply_message = bytes([1]) + "Reset_suc".encode('utf-8')
        print("Send reply message: " + "Reset_suc")
        socket.sendall(reply_message)
        continue

    user = option.split("|")[0]
    option = option.split("|")[-1]

    reply = input()
    print(reply)
    reply_message = bytes([1]) + reply.encode('utf-8')
    print("Send reply message: " + reply)
    socket.sendall(reply_message)
