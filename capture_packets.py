import pyshark
import nmap
import argparse
from utils import *

AMAZON_ECHO_MAC = '7c:d5:66:2a:44:3f'

def port_scan():
    """
    Perform a port scan on all hosts in the nmap PortScanner object.

    Args:
        nm (nmap.PortScanner): An optional nmap PortScanner object.

    Returns:
        None
    """
    nm=nmap.PortScanner()
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)

            lport = list(nm[host][proto].keys())
            lport.sort()
            for port in lport:
                print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

def analyze_echo_traffic(captured_packets):
    """
    Analyze captured packets to extract Echo-related traffic.

    Args:
        captured_packets: A list of captured packets.

    Returns:
        echo_traffic: A list of packets related to the Amazon Echo.
    """
    echo_traffic = []
    for packet in captured_packets:
        if AMAZON_ECHO_MAC in str(packet):
            echo_traffic.append(packet)
    return echo_traffic

def create_packet_statistics(captured_packets):
    """
    Create and print various packet statistics.

    Args:
        captured_packets: A list of captured packets.

    Returns:
        None
    """
    total_packets = len(captured_packets)
    print(f"Amazon Echo MAC: {AMAZON_ECHO_MAC}")
    print(f"Total Packets: {total_packets}\n")
    packet_lengths = [len(packet) for packet in captured_packets]

    packet_length_statistics(packet_lengths, total_packets)
    plot_packet_lengths(packet_lengths, args)
    protocol_distribution(captured_packets)
    most_common_ports(captured_packets)
    ipv4_ipv6_count(captured_packets)
    plot_name_distribution(captured_packets, args)
    packet_timegap_statistics(captured_packets, total_packets)

    # Calculate and print the average TTL
    average_ttl = calculate_average_ttl(echo_traffic)
    print(f"Average TTL of Echo-related packets: {average_ttl}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze captured packets and calculate average TTL.")
    parser.add_argument("file", help="Packet capture file to analyze")
    parser.add_argument("-p", "--port-scan", action="store_true", help="Perform a port scan on the hosts")

    args = parser.parse_args()

    if args.port_scan:
        port_scan()

    # Analyze the captured packets from the specified file
    try:
        captured_packets = pyshark.FileCapture(args.file)
    except FileNotFoundError:
        print(f"Error: File {args.file} not found.")
        exit(1)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)

    echo_traffic = analyze_echo_traffic(captured_packets)
    create_packet_statistics(echo_traffic)