import pyshark
import nmap
import argparse
import matplotlib.pyplot as plt
from datetime import datetime

AMAZON_ECHO_MAC = '7c:d5:66:2a:44:3f'

def port_scan():
    """
    Perform a port scan on all hosts in the nmap PortScanner object.

    Args:
        nm (nmap.PortScanner): An optional nmap PortScanner object.

    Prints information about open ports on all scanned hosts.
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

def calculate_average_ttl(packets):
    """
    Calculate the average Time to Live (TTL) value of a list of packets.

    Args:
        packets: A list of packets with TTL values.

    Returns:
        average_ttl: The average TTL value.
    """
    total_ttl = 0
    ttl_packets = len(packets)
    for packet in packets:
        try:
            total_ttl += int(packet.ip.ttl)
        except:
            ttl_packets -= 1
    average_ttl = total_ttl / ttl_packets
    return average_ttl

def plot_packet_lengths(packet_lengths):
    """
    Plot a histogram to visualize the distribution of packet lengths.

    Args:
        packet_lengths (list): A list containing the lengths of packets.

    Returns:
        None
    """
    plt.hist(packet_lengths, bins=20, color='blue', alpha=0.7)
    plt.title('Packet Length Distribution')
    plt.xlabel('Packet Length (bytes)')
    plt.ylabel('Frequency')
    try:
        filename = args.file.split('_')
        filename = '_'.join(filename[0:3])
        plt.savefig(f'{filename}_plot.png')
    except:
        pass
    plt.close()

def analyze_traffic(captured_packets, target_mac):
    """
    Filter captured packets based on a target MAC address.

    Args:
        captured_packets (list): A list of captured packets.
        target_mac (str): The MAC address to filter packets.

    Returns:
        relevant_traffic (list): A list of packets containing the target MAC address.
    """
    relevant_traffic = []
    for packet in captured_packets:
        if target_mac in str(packet):
            relevant_traffic.append(packet)
    return relevant_traffic

def create_packet_statistics(captured_packets):
    """
    Create and print various packet statistics.

    Args:
        captured_packets: A list of captured packets.
    """
    total_packets = len(captured_packets)
    print(f"Amazon Echo MAC: {AMAZON_ECHO_MAC}")
    print(f"Total Packets: {total_packets}")

    packet_lengths = [len(packet) for packet in captured_packets]
    min_length = min(packet_lengths)
    max_length = max(packet_lengths)
    avg_length = sum(packet_lengths) / total_packets
    print(f"Minimum Packet Length: {min_length} bytes")
    print(f"Maximum Packet Length: {max_length} bytes")
    print(f"Average Packet Length: {avg_length} bytes")
    plot_packet_lengths(packet_lengths)

    protocol_distribution = {}
    for packet in captured_packets:
        protocol = packet.transport_layer
        protocol_distribution[protocol] = protocol_distribution.get(protocol, 0) + 1

    print("Protocol Distribution:")
    for protocol, count in protocol_distribution.items():
        print(f"{protocol}: {count} packets")

    time_gaps = [(captured_packets[i].sniff_time - captured_packets[i - 1].sniff_time).total_seconds() for i in range(1, total_packets)]
    
    min_time_gap = min(time_gaps)
    max_time_gap = max(time_gaps)
    avg_time_gap = sum(time_gaps) / (len(time_gaps) - 1)

    print(f"Minimum Time Gap: {min_time_gap} seconds")
    print(f"Maximum Time Gap: {max_time_gap} seconds")
    print(f"Average Time Gap: {avg_time_gap} seconds")

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