import pyshark
import nmap

def port_scan(nm=nmap.PortScanner()):
    """
    Perform a port scan on all hosts in the nmap PortScanner object.

    Args:
        nm (nmap.PortScanner): An optional nmap PortScanner object.

    Prints information about open ports on all scanned hosts.
    """
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

port_scan()

# Define the interface for capturing WLAN traffic
interface = 'ciscodump'

# Define a capture filter (you may need to adjust this based on your specific requirements)
capture_filter = 'host <AMAZON_ECHO_IP>'

# Define the file to save the captured packets
output_file = 'captured_packets.pcap'

# Start capturing packets
capture = pyshark.LiveCapture(interface=interface) #, display_filter=capture_filter)

try:
    # Start capturing and write to file
    capture.sniff(packet_count=100, timeout=10)
    capture.close()
    print(f'Captured {len(capture)} packets. Saved to {output_file}')
except Exception as e:
    print(f'An error occurred: {e}')

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
        if 'AMAZON_ECHO_IP' in str(packet):
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
    for packet in packets:
        total_ttl += int(packet.ip.ttl)
    average_ttl = total_ttl / len(packets)
    return average_ttl

# Analyze the captured packets and display or process Echo-related traffic
#captured_packets = pyshark.FileCapture(output_file)
#echo_traffic = analyze_echo_traffic(captured_packets)

# Calculate and print the average TTL
#average_ttl = calculate_average_ttl(echo_traffic)
#print(f"Average TTL of Echo-related packets: {average_ttl}")
