# Sample PCAP Test Data

This directory contains sample PCAP files for integration testing.

## Generating Test PCAPs

Test PCAP files can be generated using scapy. Here's an example script:

```python
from scapy.all import *

# Basic TCP connection
def create_tcp_connection_pcap(filename):
    packets = []
    
    # SYN
    syn = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="S", seq=1000)
    packets.append(syn)
    
    # SYN-ACK
    synack = Ether()/IP(src="192.168.1.200", dst="192.168.1.100")/TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
    packets.append(synack)
    
    # ACK
    ack = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001)
    packets.append(ack)
    
    # Data
    data = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001)/Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    packets.append(data)
    
    # FIN
    fin = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="FA", seq=1050, ack=2001)
    packets.append(fin)
    
    wrpcap(filename, packets)

# UDP packet exchange
def create_udp_exchange_pcap(filename):
    packets = []
    
    # DNS query
    query = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=54321, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
    packets.append(query)
    
    # DNS response
    response = Ether()/IP(src="8.8.8.8", dst="192.168.1.100")/UDP(sport=53, dport=54321)/DNS(qr=1, aa=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34"))
    packets.append(response)
    
    wrpcap(filename, packets)

# Fragmented IP packets
def create_fragmented_pcap(filename):
    packets = []
    
    # Large payload that will be fragmented
    payload = b"A" * 3000
    
    # Create fragmented packets manually
    frag1 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200", flags="MF", frag=0, id=12345)/UDP(sport=12345, dport=80)/Raw(payload[:1480])
    packets.append(frag1)
    
    frag2 = Ether()/IP(src="192.168.1.100", dst="192.168.1.200", frag=185, id=12345)/Raw(payload[1480:])
    packets.append(frag2)
    
    wrpcap(filename, packets)

if __name__ == "__main__":
    create_tcp_connection_pcap("tcp_connection.pcap")
    create_udp_exchange_pcap("udp_exchange.pcap")
    create_fragmented_pcap("fragmented.pcap")
```

## Test Data Types

The following types of test data are useful for Dshell testing:

1. **Basic TCP Connection** - SYN, SYN-ACK, ACK, data, FIN sequence
2. **UDP Packet Exchange** - Simple request/response (e.g., DNS)
3. **Fragmented IP Packets** - For testing IP defragmentation
4. **Multi-connection PCAP** - Multiple concurrent connections
5. **Malformed Packets** - For error handling tests

## Using Test Data in Tests

Test fixtures in `conftest.py` provide mock packet objects that don't require actual PCAP files.
For integration tests that need real PCAP files, use the `temp_pcap_file` fixture or generate
test data using the scripts above.
