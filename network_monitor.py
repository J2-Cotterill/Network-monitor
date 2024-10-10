from scapy.all import sniff

def analyse_packet(packet):
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"[INFO] New Packet: {ip_layer.src} -> {ip_layer.dst}")

    if packet.haslayer('TCP'):
        tcp_layer = packet['TCP']
        print(f"[TCP] Source Port: {tcp_layer.sport}, Dest Port: {tcp_layer.dport}")
    
    if packet.haslayer('UDP'):
        udp_layer = packet['UDP']
        print(f"[UDP] Source Port: {udp_layer.sport}, Dest Port: {udp_layer.dport}")
    
    if packet.haslayer('Raw'):
        raw_layer = packet['Raw']
        print(f"[Raw] Payload: {raw_layer.load}")

def start_sniffing(interface):
    print(f"[*] Starting packet capture on interface {interface}...")
    sniff(iface=interface, prn=analyse_packet, store=0)

if __name__ == "__main__":
    interface = input("Enter the network interface to sniff (e.g., eth0, wlan0): ")
    start_sniffing(interface)
