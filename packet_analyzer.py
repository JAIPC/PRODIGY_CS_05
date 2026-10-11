from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def analyze_packet(packet):

    if IP not in packet:
        return

    source = packet[IP].src
    destination = packet[IP].dst

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    else:
        protocol = "Other"

    print("\n--------------------------------")
    print("Packet Captured")
    print("--------------------------------")
    print("Source IP      :", source)
    print("Destination IP :", destination)
    print("Protocol       :", protocol)

    if Raw in packet:
        payload = bytes(packet[Raw].load)

        # Show only a short printable preview
        preview = payload[:50]

        print("Payload Preview:", preview)

    else:
        print("Payload        : No application payload")


print("================================")
print("       NETWORK PACKET ANALYZER")
print("================================")

print("\nCapturing packets...")
print("Press Ctrl+C to stop.\n")

sniff(prn=analyze_packet, store=False)
