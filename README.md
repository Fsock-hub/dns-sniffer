## DNS Sniffer

A lightweight DNS packet sniffer written in pure Python using the scapy library. The tool captures DNS queries and responses on a specified network interface, extracts domain names, and logs the corresponding IP addresses. It is designed for educational purposes, network troubleshooting, and basic traffic analysis.

## Features

- Captures live DNS traffic on a chosen network interface.

- Parses both DNS queries (QR=0) and responses (QR=1).

- Extracts queried domain names and resolved IP addresses (A records).

- Prints real-time output to the console.

- Lightweight and dependency-minimal (only scapy required).

- Works on Linux, Windows, and macOS (with appropriate permissions).

## How It Works

The sniffer uses scapy to listen for UDP packets on port 53. For each packet, it checks whether the DNS layer is present.

If the packet is a query (qr == 0), it extracts the queried domain name and prints the source and destination IP addresses.

If the packet is a response (qr == 1), it extracts the domain name and iterates through the answer records. For each A record (type 1), it prints the resolved IP address.

The tool does not modify or inject packets. It only reads and displays DNS traffic.

## Installation

- Clone the repository:
  ```bash
      git clone https://github.com/Fsock-hub/dns-sniffer.git
      cd dns-sniffer
  ```
- Install the required dependency:
  ```bash
    pip install scapy
  ```
- Run the sniffer (requires root or administrator privileges):
  ```bash
    sudo python dns_sniffer.py
  ```
```On Windows, run the terminal as Administrator.```

## Usage

The script listens on all interfaces by default. To specify an interface, modify the iface parameter in the sniff() call.

Example output:
```text

[QUERY] Client 192.168.1.5 -> Server 8.8.8.8 | Searching domain: example.com.
[RESPONSE] Server 8.8.8.8 -> Client 192.168.1.5 | Domain: example.com.
   -> IP: 93.184.216.34
```

## Requirements

- Python 3.6 or higher

- Scapy library and Npcap driver

- Root/administrator privileges (required for raw socket access)

## Limitations

- Only parses A records (IPv4). AAAA, CNAME, and other record types are not processed.

- Does not support DNS over HTTPS (DoH) or DNS over TLS (DoT).

- Works only on unencrypted DNS traffic (port 53).

## Future Improvements

- Add support for AAAA (IPv6) and CNAME records.

- Log output to a file with timestamps.

- Filter by specific domains or IP ranges.

- Add statistics (number of queries, top domains).

- Support for pcap file input for offline analysis.

## Disclaimer

This tool is intended for educational purposes, network diagnostics, and authorized security testing. Do not use it to intercept traffic on networks you do not own or do not have explicit permission to monitor. The author is not responsible for any misuse or damage caused by this program.
