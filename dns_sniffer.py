from scapy.all import sniff
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR

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