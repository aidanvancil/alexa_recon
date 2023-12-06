import matplotlib.pyplot as plt

def packet_timegap_statistics(captured_packets, total_packets):
    """
    Generates packet time gap statistics

    Args:
        captured_packets: A list of captured packets.
        total_packets: Total number of packets captured.

    Returns:
        None
    """
    time_gaps = [(captured_packets[i].sniff_time - captured_packets[i - 1].sniff_time).total_seconds() for i in range(1, total_packets)]
    
    min_time_gap = min(time_gaps)
    max_time_gap = max(time_gaps)
    avg_time_gap = sum(time_gaps) / (len(time_gaps) - 1)

    print(f"Minimum Time Gap: {min_time_gap} seconds")
    print(f"Maximum Time Gap: {max_time_gap} seconds")
    print(f"Average Time Gap: {avg_time_gap} seconds\n")

def packet_length_statistics(packet_lengths, total_packets):
    """
    Generates packet length statistics

    Args:
        packet_lengths: A list of all captured packet's respective length.
        total_packets: Total number of packets captured.

    Returns:
        None
    """
    min_length = min(packet_lengths)
    max_length = max(packet_lengths)
    avg_length = sum(packet_lengths) / total_packets
    print(f"Minimum Packet Length: {min_length} bytes")
    print(f"Maximum Packet Length: {max_length} bytes")
    print(f"Average Packet Length: {avg_length} bytes\n")

def protocol_distribution(captured_packets):
    """
    Illustrates the protocol distribution across the captured packets.

    Args:
        captured_packets: A list of captured packets.

    Returns:
        None
    """
    protocol_distribution = {}
    for packet in captured_packets:
        protocol = packet.transport_layer
        protocol_distribution[protocol] = protocol_distribution.get(protocol, 0) + 1

    print("Protocol Distribution:")
    for protocol, count in protocol_distribution.items():
        print(f"{protocol}: {count} packets")
    print('\n')

def most_common_ports(captured_packets):
    """
    Obtains the most common source and destination ports for the Echo captured packets.

    Args:
        captured_packets: A list of captured packets.

    Returns:
        None
    """
    source_ports = [packet.udp.srcport for packet in captured_packets if 'udp' in packet]
    dest_ports = [packet.udp.dstport for packet in captured_packets if 'udp' in packet]

    most_common_source_port = max(set(source_ports), key=source_ports.count)
    most_common_dest_port = max(set(dest_ports), key=dest_ports.count)

    print(f"Most Common Source Port: {most_common_source_port}")
    print(f"Most Common Destination Port: {most_common_dest_port}")
    print('\n')

def ipv4_ipv6_count(captured_packets):
    """
    Counts the packets of IPV4 or IPV6 type.

    Args:
        captured_packets: A list of captured packets.

    Returns:
        None
    """
    ipv4_count = sum(1 for packet in captured_packets if 'ip' in packet and packet.ip.version == '4')
    ipv6_count = sum(1 for packet in captured_packets if 'ip' in packet and packet.ip.version == '6')

    print(f"IPv4 Packets: {ipv4_count}")
    print(f"IPv6 Packets: {ipv6_count}")
    print('\n')


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

def plot_packet_lengths(packet_lengths, args):
    """
    Plot a histogram to visualize the distribution of packet lengths.

    Args:
        packet_lengths (list): A list containing the lengths of packets.
        args (argument list): arguments from python script

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
        plt.savefig(f'{filename}_length_plot.png')
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

def plot_name_distribution(captured_packets, args):
    """
    Plot a bar chart to visualize the distribution of names.

    Args:
        captured_packets: A list of captured packets.
        args (argument list): arguments from python script

    Returns:
        None
    """
    name_count = {}
    for item in captured_packets:
        try:
            if hasattr(item, 'mdns') and item.mdns.dns_qry_name:
                name = item.mdns.dns_qry_name
                name_count[name] = name_count.get(name, 0) + 1
        except AttributeError:
            continue

    most_common_names = sorted(name_count.items(), key=lambda x: x[1], reverse=True)
    top_names = [name for name, count in most_common_names]
    counts = [count for name, count in most_common_names]

    plt.bar(top_names, counts, color='blue', alpha=0.7)
    plt.title('Name Distribution')
    plt.xlabel('Name')
    plt.ylabel('Frequency')
    plt.xticks(rotation=45, ha='right') # We are rotating for better visibility, due to long DNS server names.
    plt.tight_layout()
    try:
        filename = args.file.split('_')
        filename = '_'.join(filename[0:3])
        plt.savefig(f'{filename}_name_plot.png')
    except:
        pass
    plt.close()