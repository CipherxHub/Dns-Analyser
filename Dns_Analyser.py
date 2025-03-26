from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR, wrpcap, rdpcap
import numpy as np
import time
import json
from collections import defaultdict
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# Output files
PCAP_FILE = "dns_capture.pcap"
JSON_FILE = "output.json"
REPORT_FILE = "dns_report.pdf"
packets = []
query_counts = defaultdict(int)
timestamps = []
MARGIN_LEFT = 50
MARGIN_TOP = 750
LINE_SPACING = 20

def calculate_entropy(domain):
    """Calculate Shannon entropy of a domain name."""
    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum(p * np.log2(p) for p in prob)

def parse_dns_flags(dns):
    """Map DNS flag values to human-readable format."""
    return {
        "qr": "RESPONSE" if dns.qr else "QUERY",
        "opcode": ["QUERY", "IQUERY", "STATUS", "RESERVED"][dns.opcode],
        "aa": "TRUE" if dns.aa else "FALSE",
        "tc": "TRUE" if dns.tc else "FALSE",
        "rd": "TRUE" if dns.rd else "FALSE",
        "ra": "TRUE" if dns.ra else "FALSE",
        "rcode": ["NOERROR", "FERROR", "SFAILURE", "NERROR", "NIMPLEMENTED", "REFUSED", "RESERVED"][dns.rcode]
    }

def format_flags(flags):
    """Format the flags dictionary for better readability in the PDF."""
    return "\n".join([f"  {key}: {value}" for key, value in flags.items()])

def generate_remark(entropy, flags):
    """Generate remarks based on entropy and DNS flags."""
    if entropy > 3.5:
        return "High entropy domain name - Possible DGA or DNS Tunneling"
    if flags["rcode"] == "REFUSED":
        return "DNS query refused by the server"
    if flags["qr"] == "RESPONSE" and flags["rcode"] != "NOERROR":
        return "Unsuccessful DNS response - Possible misconfiguration or attack"
    return "Normal query"

def packet_handler(packet):
    if packet.haslayer(DNS) and packet.haslayer(UDP):
        packets.append(packet)

def capture_dns_packets(duration):
    """Capture DNS packets for a user-defined duration."""
    print(f"Capturing DNS traffic for {duration} seconds...")
    sniff(filter="udp port 53", prn=packet_handler, store=False, timeout=duration)
    if packets:
        wrpcap(PCAP_FILE, packets)
        print(f"Captured packets saved to {PCAP_FILE}")

def analyze_pcap():
    """Analyze the captured DNS packets and save details to JSON and a PDF report."""
    print("Analyzing captured DNS traffic...")
    captured_packets = rdpcap(PCAP_FILE)
    analysis_results = []
    
    c = canvas.Canvas(REPORT_FILE, pagesize=letter)
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(300, 770, "DNS Traffic Analysis Report")
    c.setFont("Helvetica", 12)
    y_position = MARGIN_TOP
    
    for packet in captured_packets:
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            dns = packet[DNS]
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            dns_query = packet[DNSQR].qname.decode('utf-8') if packet.haslayer(DNSQR) else "Unknown"
            entropy = calculate_entropy(dns_query)
            flags = parse_dns_flags(dns)
            formatted_flags = format_flags(flags)
            remark = generate_remark(entropy, flags)
            
            query_counts[dns_query] += 1
            timestamps.append(time.time())
            
            dns_info = {
                "source_ip": ip_src,
                "destination_ip": ip_dst,
                "query": dns_query,
                "entropy": entropy,
                "qdcount": dns.qdcount,
                "ancount": dns.ancount,
                "nscount": dns.nscount,
                "arcount": dns.arcount,
                "flags": flags,
                "remark": remark
            }
            analysis_results.append(dns_info)
            
            c.setFont("Helvetica-Bold", 12)
            c.drawString(MARGIN_LEFT, y_position, f"Query: {dns_query}")
            c.setFont("Helvetica", 12)
            c.drawString(MARGIN_LEFT, y_position - LINE_SPACING, f"Source: {ip_src} -> Destination: {ip_dst}")
            c.drawString(MARGIN_LEFT, y_position - 2 * LINE_SPACING, f"Entropy: {entropy:.4f}")
            c.drawString(MARGIN_LEFT, y_position - 3 * LINE_SPACING, "Flags:")
            for i, line in enumerate(formatted_flags.split("\n")):
                c.drawString(MARGIN_LEFT + 20, y_position - (4 + i) * LINE_SPACING, line)
            c.setFillColor(colors.red)
            c.drawString(MARGIN_LEFT, y_position - (5 + len(formatted_flags.split("\n"))) * LINE_SPACING, f"Remark: {remark}")
            c.setFillColor(colors.black)
            c.drawString(MARGIN_LEFT, y_position - (6 + len(formatted_flags.split("\n"))) * LINE_SPACING, "-------------------------------------------------")
            y_position -= 140 + (len(formatted_flags.split("\n")) * LINE_SPACING)
            if y_position < 100:
                c.showPage()
                c.setFont("Helvetica", 12)
                y_position = MARGIN_TOP
    
    c.save()
    
    # Save results to JSON file
    with open(JSON_FILE, "w") as f:
        json.dump(analysis_results, f, indent=4)
    print(f"Analysis results saved to {JSON_FILE}")
    print(f"Report saved to {REPORT_FILE}")

if __name__ == "__main__":
    print("Developed by Group 5")
    duration = int(input("Enter the duration (in seconds) for DNS packet capture: "))
    capture_dns_packets(duration)
    analyze_pcap()
