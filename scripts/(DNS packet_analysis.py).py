# coding: utf-8
from scapy.all import rdpcap

packets = rdpcap("dns.cap")  # Replace with the correct path if needed
print(f"Loaded {len(packets)} packets.")
packets.summary()
packets[0].show()
dns_packets = [pkt for pkt in packets if pkt.haslayer("DNS")]
print(f"Found {len(dns_packets)} DNS packets.")
for pkt in dns_packets:
    if pkt["DNS"].qr == 0:  # qr=0 means it's a query
        print(f"Query: {pkt['DNS'].qd.qname.decode()}")
from scapy.all import wrpcap

wrpcap("filtered_dns.pcap", dns_packets)
print("Filtered DNS packets saved to filtered_dns.pcap")
# Filtered DNS packets saved to filtered_dns.pcap
packets[1].show()
