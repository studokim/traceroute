from socket import *
import re
import argparse
import struct
from typing import Tuple


def print_line(ip: str, hop: int):
    print("{:2}: {:16}".format(hop, ip))


def unpack(data: bytes) -> dict:
    #  unpack the raw received IP and ICMP header informations to a dict
    names = [
        "type", "code", "checksum",
        "packet_id", "seq_number"
    ]
    unpacked_data = struct.unpack("!BBHHH", data[20:28])
    return dict(zip(names, unpacked_data))


def send_udp(socket: socket, dest_ip: str, dest_port: int, ttl: int):
    socket.setsockopt(SOL_IP, IP_TTL, ttl)
    socket.sendto("hello world".encode(), (dest_ip, dest_port))


def get_icmp(socket: socket, wait_time: int) -> Tuple[bool, str]:
    socket.settimeout(wait_time)
    try:
        data, address = socket.recvfrom(576)
    except timeout:
        return (False, "no reply")
    reply = unpack(data)
    if (reply["type"] == 3 and (reply["code"] == 0 or reply["code"] == 1)):
        # network or host unreachable
        return (False, "Destination unreachable")
    if (reply["type"] == 11 and reply["code"] == 0 or  # TTL expired in transit
            reply["type"] == 3):
        return (True, address[0])  # ip address
    return (False, "type: {}, code: {}".format(reply["type"], reply["code"]))


def run_loop(dest_ip: str, port: int, wait_time: int, attempts: int, hop_limit: int):
    with (socket(AF_INET, SOCK_DGRAM, getprotobyname("udp")) as udp_socket,
          socket(AF_INET, SOCK_RAW, getprotobyname("icmp")) as icmp_socket):
        for hop in range(1, hop_limit + 1):
            for attempt in range(attempts):
                send_udp(udp_socket, dest_ip, port, hop)
                ok, ip = get_icmp(icmp_socket, wait_time)
                if ok:
                    print_line(ip, hop)
                    if (ip == dest_ip):
                        return
                    break
            if not ok:
                print_line(ip, hop)
                if (ip != "no reply"):
                    return


def ip_regex(arg_value, pat=re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")):
    if not pat.match(arg_value):
        raise argparse.ArgumentTypeError("IP is not correct")
    return arg_value


def parse_args() -> str:
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", type=ip_regex, help="the IP address")
    parser.add_argument("-t", "--timeout", type=int, default=3,
                        help="time to wait for each reply")
    parser.add_argument("-a", "--attempts", type=int, default=3,
                        help="number of attempts for each hop")
    parser.add_argument("-m", "--hops", type=int, default=30,
                        help="max number of hops")
    args = parser.parse_args()
    return args.ip, args.timeout, args.attempts, args.hops


def main() -> int:
    port = 65535
    dest_ip, wait_time, attemps, hop_limit = parse_args()
    run_loop(dest_ip, port, wait_time, attemps, hop_limit)
    return 0


if __name__ == "__main__":
    main()
