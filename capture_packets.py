import pyshark

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

# Get Echo Traffic
def analyze_echo_traffic(captured_packets):
    echo_traffic = []
    for packet in captured_packets:
        if 'AMAZON_ECHO_IP' in str(packet):
            echo_traffic.append(packet)

    return echo_traffic

# Calculate the average TTL of packets
def calculate_average_ttl(packets):
    total_ttl = 0
    for packet in packets:
        total_ttl += int(packet.ip.ttl)
    average_ttl = total_ttl / len(packets)
    return average_ttl

# Analyze the captured packets
#captured_packets = pyshark.FileCapture(output_file)
#echo_traffic = analyze_echo_traffic(captured_packets)

# Display or process Echo-related traffic
#for packet in echo_traffic:
#    print(packet)

# Calculate and print the average TTL
#average_ttl = calculate_average_ttl(echo_traffic)
#print(f"Average TTL of Echo-related packets: {average_ttl}")