import os
import sys

try:
    from scapy.all import sniff
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    
except ImportError:
    print("[*] Scapy module not found. Attempting auto-installation...")
    exit_code = os.system(f"{sys.executable} -m pip install scapy")
    
    if exit_code != 0:
        print("[-] Auto-installation failed. Please run: pip install scapy")
        sys.exit(1)
        
    from scapy.all import sniff
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    print("[+] Scapy installed and imported successfully.")

def check_windows_environment():
    is_windows = (os.name == 'nt')
    
    if is_windows:
        try:
            sniff(count=1, timeout=0.1)
            npcap_failed = False
        except Exception:
            npcap_failed = True
            
        if is_windows and npcap_failed:
            print("\n" + "="*60)
            print("[-] CRITICAL ERROR: Npcap driver is missing!")
            print("[*] To run this sniffer on Windows, you must install Npcap.")
            print("[*] Download it from the official site: https://npcap.com")
            print("="*60 + "\n")
            sys.exit(1)

check_windows_environment()

print("[+] Environment check passed! Starting DNS Sniffer...")

def process_dns_packet(packet):
    if packet.haslayer(DNS):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        dns_layer = packet[DNS]

        if dns_layer.qr == 0:
            qname = dns_layer[DNSQR].qname.decode('utf-8')
            print(f'[QUERY] Client {ip_src} -> Server {ip_dst} | Searching domain: {qname}')

        elif dns_layer.qr == 1:
            qname = dns_layer[DNSQR].qname.decode('utf-8')
            print(f'[RESPONSE] Server {ip_dst} -> Client {ip_src} | Domain: {qname}')

            if dns_layer.ancount > 0:

                for i in range(dns_layer.ancount):
                    try:
                        dns_record = dns_layer[DNSRR][i]
                        if dns_record.type == 1:
                            print(f"   -> IP: {dns_record.rdata}")
                    except:
                        pass

def start_sniff():
    print('[*] Starting sniffing DNS packets...')

    sniff(filter='udp port 53', prn=process_dns_packet, store=0)

if __name__ == '__main__':
    start_sniff()
