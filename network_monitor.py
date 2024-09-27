from scapy.all import sniff

# Function to analyze captured packets
def analyze_packet(packet):
    # Check if the packet has an IP layer
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"[INFO] New Packet: {ip_layer.src} -> {ip_layer.dst}")

    # Check if the packet has a TCP layer
    if packet.haslayer('TCP'):
        tcp_layer = packet['TCP']
        print(f"[TCP] Source Port: {tcp_layer.sport}, Dest Port: {tcp_layer.dport}")
    
    # Check if the packet has a UDP layer
    if packet.haslayer('UDP'):
        udp_layer = packet['UDP']
        print(f"[UDP] Source Port: {udp_layer.sport}, Dest Port: {udp_layer.dport}")
    
    # Check if the packet has a Raw layer (for payload)
    if packet.haslayer('Raw'):
        raw_layer = packet['Raw']
        print(f"[Raw] Payload: {raw_layer.load}")

# Sniff packets and analyze them using the callback function
def start_sniffing(interface):
    print(f"[*] Starting packet capture on interface {interface}...")
    sniff(iface=interface, prn=analyze_packet, store=0)

if __name__ == "__main__":
    # Start sniffing on interface (e.g., 'eth0' or 'wlan0')
    interface = input("Enter the network interface to sniff (e.g., eth0, wlan0): ")
    start_sniffing(interface)
