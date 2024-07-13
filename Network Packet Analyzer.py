from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    """
    Callback function to process each captured packet.

    Parameters:
    packet (scapy.packet.Packet): The captured packet.
    """
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")

        if protocol == 6:  # TCP Protocol
            print("Protocol: TCP")
            if TCP in packet:
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                print(f"Source Port: {tcp_sport}")
                print(f"Destination Port: {tcp_dport}")
                if Raw in packet:
                    print(f"Payload: {packet[Raw].load}")

        elif protocol == 17:  # UDP Protocol
            print("Protocol: UDP")
            if UDP in packet:
                udp_sport = packet[UDP].sport
                udp_dport = packet[UDP].dport
                print(f"Source Port: {udp_sport}")
                print(f"Destination Port: {udp_dport}")
                if Raw in packet:
                    print(f"Payload: {packet[Raw].load}")

        print("="*50)

def main():
    """
    Main function to start packet sniffing.
    """
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
