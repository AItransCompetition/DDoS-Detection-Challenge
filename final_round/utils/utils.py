import ipaddress
import socket
import dpkt

def get_flow_id(packet):
    eth = dpkt.ethernet.Ethernet(packet)
    assert isinstance(eth.data, dpkt.ip.IP)
    ip = eth.data
    src_ip = ipaddress.IPv4Address(socket.inet_ntoa(ip.src))
    dst_ip = ipaddress.IPv4Address(socket.inet_ntoa(ip.dst))
    proto = ip.p
    assert proto == 6 or proto == 17, 'proto should be 6 or 17.'
    if proto == 17:
        tcp = ip.data
        src_port = tcp.sport
        dst_port = tcp.dport
    if proto == 6:
        udp = ip.data
        src_port = udp.sport
        dst_port = udp.dport
    return str(src_ip) + '-' + str(dst_ip) + '-' + str(src_port) + '-' + str(dst_port) + '-' + str(proto)
    

def load_pcap(filepath: str, packet_number_limit = 0):
    pcap = dpkt.pcap.Reader(open(filepath, 'rb'))
    packets = []
    for timestamp, packet in pcap:
        packets.append((timestamp, packet))
        if packet_number_limit > 0:
            if len(packets) == packet_number_limit: break
    return packets

if __name__ == '__main__':
    packets = load_pcap('pcap.pcap', 10)
    for timestamp, packets in packets:
        print(timestamp, get_flow_id(packets))