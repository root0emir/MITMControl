from scapy.all import *
import socket
import time
import random

# ASCII Art to send as part of packets
ASCII_ART = r"""


⠀⠀⠀⢰⠇⠀⠀⠀⠀⠀⠀⡼⠁⡴⣼⢄⠀⠀⠀⢸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠆⢠⡄⣀⡄⡆⢣⢏⣆⠃⠀⠀⠀⠀⠀⠀⠀⢹⡀⠀⠀⠹
⠀⠀⠀⡎⠀⠀⠀⠀⠀⠀⢠⠃⡰⢱⣏⡿⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣸⣏⢻⢻⡈⡞⠘⠀⠀⠀⠀⠀⠀⠀⠀⠀⢇⠀⠀⠀
⠀⠀⢸⠃⠀⠀⠀⠀⠀⠀⡜⢰⠃⠀⠈⠁⠀⠀⢰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠀⠀⠀⠀⠀⢠⠀⠀⠀⠀⠉⠁⠁⠀⠀⠀⢣⠀⠀⠀⠀⠀⠀⠀⢸⡀⠀⠀
⣄⣀⡾⠀⠀⠀⠀⠀⠀⢰⣧⠇⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀
⠋⢹⡇⠀⠀⠀⠀⠀⠀⣼⡞⠀⠀⠀⠀⠀⠀⠀⡈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⡼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡄⠀⠀⠀⠀⠀⠀⠀⢻⠀⠀
⠀⣸⠀⠀⠀⠀⠀⠀⠀⣿⠁⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠁⠀⠀⠀⠀⢠⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀
⠀⡇⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⢰⠃⠀⠀⠀⠀⠀⠀⢀⡎⠀⠀⠀⠀⠀⠀⠀⢠⠇⠀⠀⠀⠀⠀⣸⣇⢀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀
⠀⠃⠀⠀⠀⠀⠀⠀⢸⠁⠀⠀⠀⣰⠀⠀⢠⡟⠀⠀⠀⠀⠀⠀⣠⠏⠀⠀⠀⠀⠀⠀⠀⢀⡞⠀⠀⠀⣠⠴⢲⡏⠙⢧⠀⠀⢧⠀⠀⠈⠁⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠅⠀
⢸⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⢀⣴⠟⠚⣽⣿⠉⠉⠙⠒⠦⣄⡴⠃⠀⠀⠀⠀⡞⠀⠀⢀⡞⠀⠀⠠⠎⠁⠀⡜⠀⠀⠈⢳⡀⠀⠳⡀⠀⠀⠀⠀⠀⢸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣸⠀⠀⠀⠀⠀⠀⠀⣿⣀⣴⡿⠃⣠⡞⣹⠃⠀⠀⠀⠀⣰⠏⠉⠀⠀⠀⡔⡸⠁⠀⣠⡞⠀⠀⠀⠀⠀⠀⢰⠁⠀⠀⠀⠀⠹⣄⠀⠙⢦⠳⡀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢹⠀⠀⠀⠀⠀⠀⠀⡿⢋⡾⢁⡴⠋⣼⠃⠀⠀⠀⣠⢞⡏⠀⠀⠀⠀⡸⡱⠁⢀⡼⢡⠇⠀⠀⠀⠀⠀⣠⠃⠀⠀⣀⣀⡀⠀⠈⢷⡀⠀⠑⣝⣦⡀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢈⠀⠀⠀⠀⠀⠀⠀⣷⢟⣴⠏⠀⣼⠃⠀⢀⣤⣞⣁⡞⠀⠀⠀⠀⣰⡿⣁⡴⠋⢀⡞⠀⠀⠀⠀⠀⣰⠋⣠⠔⣊⣁⣤⣴⣶⣾⣿⣿⣿⣶⣿⣿⣿⣾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠘⠀⠀⠀⠀⠀⠀⠀⣿⠟⠁⣷⣾⣥⣴⣶⣿⣷⣶⣿⣿⣵⣦⣀⣼⣿⠟⠉⠀⠀⡜⠀⠀⠀⠀⢀⡾⠁⢘⣽⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠙⠛⢿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠸⠀⠀⠀⠀⠀⠀⠀⢹⢀⣤⣿⣿⡿⠟⠋⢉⣿⣿⣿⣿⣿⣿⣿⣞⠁⠀⠀⠀⡼⠁⠀⠀⢀⣴⠏⠀⠀⠈⠿⠋⢹⣿⣻⣿⠛⠻⡿⢦⣶⠀⠀⣸⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠸⣟⢿⣿⣏⠀⠀⠀⢸⣿⣿⣿⠋⠙⣿⣴⡏⠀⠀⠀⡼⠁⠀⠀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠘⣿⠟⠙⣄⣠⡟⠂⣼⠀⢠⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡤⠀⡄⠀⠀⠀⠀⠀⠀⢻⡆⢻⣿⡄⠀⠀⠸⣟⠁⠘⠦⠴⠃⢸⡇⠀⠀⡼⠁⣠⣤⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣄⠀⣇⣀⣇⣠⠇⠀⡞⢟⣟⡜⠀⠀⠀⠀⠀⢠⠆⠀⡀⠀
⢻⡆⢧⠀⠀⠀⠀⠀⠀⠈⣿⡄⠙⣿⣄⠀⠀⠙⣆⣸⣁⣀⡿⠼⠀⢀⡾⠷⣿⠟⠁⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠁⠀⠀⠙⠛⢀⣾⠟⠀⠀⠀⠀⠀⣠⠟⠀⠀⡇⠀
⠃⡇⠸⡄⠀⠀⠀⠀⠀⠀⠘⢷⡀⠀⠈⠶⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⢠⠄⣢⡿⠋⠀⠀⠀⠀⣠⠞⠁⠀⠀⢸⠓⠶
⠀⢻⠀⢣⠀⠀⣄⠀⠀⠀⠀⠈⠳⣄⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠑⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⢁⡴⠋⠀⠀⠀⣠⡴⠛⠁⠀⠀⠀⡇⣼⠀⠀
⠀⠈⡆⠈⢧⡀⠈⠙⠢⢤⣀⠀⠀⠈⠳⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⢀⣀⡤⠖⠋⣹⡇⠀⠀⠀⠀⢀⣇⡇⠀⠀
⠶⢶⣧⠀⠀⠑⢄⡀⠀⠀⠈⢻⡗⣶⡤⣤⣽⣳⣦⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⡀⠀⠀⠀⠀⠰⠿⠓⠛⠉⠁⠀⠀⢠⡿⠀⠀⠀⠀⠀⢸⢾⠀⠀⠀
⠀⠀⠘⡆⠀⠀⠀⠙⠲⣶⣤⣄⣙⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⡶⠂⠀⠁⠀⠀⠀⠀⠀⠀⠈⢻⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠁⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀
⠀⠀⠀⢳⠀⠀⠀⠀⠀⢠⠈⣿⡇⠀⢹⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡟⠀⠀⠀⠀⠀⢰⡿⠀⠀⠀⠀
⠀⠀⠀⢸⡆⠀⠀⠀⠀⠸⡄⢻⡇⠀⠀⢻⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡜⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣸⠁⠀⠀⠀⠀⢀⣿⠃⠀⠀⠀⠀
⠀⠀⠀⢸⢻⡄⠀⠀⠀⠀⢧⢸⣇⠀⠀⠀⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⡀⠀⠀⠀⠀⠀⠀⣠⠞⠁⠀⠀⠀⠀⠀⠀⠀⣠⡶⠋⠁⢠⠇⠀⠀⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀
⠀⠀⠀⢠⠀⣷⡄⠀⠀⠀⠈⣎⣿⠀⠀⠀⠀⠀⠙⠶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠤⠚⠁⠀⠀⠀⠀⠀⠀⣀⣴⣾⣻⣄⠀⢠⠏⠀⠀⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⢰⠇⠹⣄⠀⠀⠀⠘⣿⣆⠀⠀⠀⠀⠀⠀⠀⠉⠓⠦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡴⢿⢏⡽⢿⠉⠻⣴⠏⠀⠀⠀⠀⣠⠋⠀⠀⠀⠀⠀⠀⠀⣀
⠀⠀⠀⣀⡼⠀⠀⠘⢧⡀⠀⠀⠘⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠓⢦⣄⡀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣾⣿⣿⣿⠟⠉⠁⡞⢀⡼⠃⠀⠀⠀⣠⠞⠁⠀⠀⠀⠀⠀⠀⢠⣾⡿
⠀⠀⢠⣿⠃⠀⠀⠀⠀⠙⢦⡀⠀⠈⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⣹⣷⣦⣀⣀⣤⣶⢟⣻⣿⠟⠋⠉⠁⠀⠀⢀⣷⠟⠀⠀⢀⡴⠞⠁⠀⠀⠀⠀⠀⠀⢀⣼⣿⣯⡴
⢀⣣⣿⠏⠀⠀⠀⠀⠀⠀⠀⠙⠢⣄⡀⠙⣆⠀⠀⠀⢀⡖⠲⢤⠀⠀⠀⠀⢸⡥⢿⣿⣿⣿⣾⣫⡟⠁⠀⠀⠀⠀⠀⠀⠶⠯⣤⣤⡶⠚⠉⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⡟⠁⠀
⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠓⠾⠷⠄⢠⣟⡀⢠⠏⠀⠀⠀⠀⠀⠹⡌⠛⠻⣄⣾⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣶⣄⣤⣄⡀⠀⠀⣀⣴⣿⣿⣿⡿⠁⠀⠀
⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠀⠀⠀⢿⣀⣀⣾⣻⣀⣀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣷⣟⣻⣿⣿⣿⣿⣿⠃⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣸⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⡉⢹⣿⡏⣇⣩⡷⠀⠀⠀⣀⣤⣾⠟⠁⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀

"""

# configuration
UDP_PORTS = [12345, 53, 123, 161, 500]  # UDP target ports (DNS, NTP, SNMP)
TCP_PORTS = [80, 443, 22, 25, 8080]     # TCP target ports (HTTP, HTTPS, SSH, SMTP)
PACKET_COUNT = 50  # number of packets to send per target port

def detect_arp_spoof():
    """Detect ARP spoofing by monitoring ARP packets."""
    print("Checking for ARP spoofing...")
    arp_table = {}
    packets = sniff(count=50, filter="arp", timeout=5)  
    for packet in packets:
        if ARP in packet and packet[ARP].op == 2: 
            mac = packet[ARP].hwsrc
            ip = packet[ARP].psrc
            if ip in arp_table and arp_table[ip] != mac:
                print(f"[Detected] ARP Spoofing Detected! IP: {ip}, Fake MAC: {mac}")
                return ip
            arp_table[ip] = mac
    print("[Info] No ARP spoofing detected.")
    return None

def send_udp_packets(target_ip):
    """Send ASCII art over UDP to target ports."""
    print("[Action] Sending UDP packets...")
    for udp_port in UDP_PORTS:
        for i in range(PACKET_COUNT):
            try:
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_sock.sendto(ASCII_ART.encode(), (target_ip, udp_port))
                print(f"[UDP] Packet {i + 1}/{PACKET_COUNT} sent to port {udp_port}.")
            finally:
                udp_sock.close()

def send_tcp_packets(target_ip):
    """Send ASCII art over TCP to target ports."""
    print("[Action] Sending TCP packets...")
    for tcp_port in TCP_PORTS:
        for i in range(PACKET_COUNT):
            try:
                tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp_sock.connect((target_ip, tcp_port))
                tcp_sock.sendall(ASCII_ART.encode())
                print(f"[TCP] Packet {i + 1}/{PACKET_COUNT} sent to port {tcp_port}.")
            except Exception as e:
                print(f"[Error] TCP sending failed: {e}")
            finally:
                tcp_sock.close()
            time.sleep(0.1)

def send_icmp_packets(target_ip):
    """Send ICMP Echo Request (Ping) packets."""
    print("[Action] Sending ICMP packets...")
    for i in range(PACKET_COUNT):
        try:
            packet = IP(dst=target_ip) / ICMP() / ASCII_ART
            send(packet, verbose=False)
            print(f"[ICMP] Ping packet {i + 1}/{PACKET_COUNT} sent.")
        except Exception as e:
            print(f"[Error] ICMP sending failed: {e}")

def send_raw_packets(target_ip):
    """Send random RAW TCP packets."""
    print("[Action] Sending RAW TCP packets...")
    for i in range(PACKET_COUNT):
        try:
            packet = IP(dst=target_ip) / TCP(dport=random.choice(TCP_PORTS), flags="S") / ASCII_ART
            send(packet, verbose=False)
            print(f"[RAW] Random TCP packet {i + 1}/{PACKET_COUNT} sent.")
        except Exception as e:
            print(f"[Error] RAW packet sending failed: {e}")

if __name__ == "__main__":
    print("Welcome - Starting Tool...")
    
    # Run detection mechanism
    attacker_ip = detect_arp_spoof()
    
    if attacker_ip:
        # Packet sending mechanisms
        send_udp_packets(attacker_ip)
        send_tcp_packets(attacker_ip)
        send_icmp_packets(attacker_ip)
        send_raw_packets(attacker_ip)
        print("[Complete] Cute anime girls and disruptive packets sent to the attacker!")
    else:
        print("[Info] No MITM attack detected. Exiting tool.")
