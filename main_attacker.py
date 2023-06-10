import scapy.all as scapy

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
    if packet[scapy.ICMP] and packet[scapy.ICMP].id == END_TRANSMISSION_ID:
        return True
    else:
        return False


def receive_transmission():
    return scapy.sniff(filter="icmp and dst 137.194.150.103", stop_filter=stop_fnc)  # ,prn=lambda packet: packet.show()


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    message = ""
    capture = receive_transmission()
    capture = capture[1:len(capture) - 1]
    for packet in capture:
        message += packet[scapy.ICMP].payload.load.decode("utf-8")
    print(message)
    write_string_to_file("data.txt", message)