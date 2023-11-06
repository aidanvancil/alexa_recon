
# Alexa Reconnaissance

## Abstract 
In this project, our team will demonstrate what the Amazon Echo sends out and receives upon activation of different voice assertions. As a stretch goal we will focus on the same analysis for when the Amazon Echo pairs with Bluetooth devices. Our team presumes the Echo is already encrypted with HTTPS during transit and TLS at rest, so we will utilize Burp Suite, a tool used for packet analysis in combination with Wireshark. Understandably so, capturing WiFi traffic can be difficult, so our team will specifically take Wireshark WLAN capturing in mind. The analysis performed will be on the average latency and the different packets being sent out to the external Amazon server upon varied voice assertions or song requests upon pairing with a Bluetooth device. It will be our focus to see how often the Echo is listening in to hear for an assertion and so on. It is possible this project might encompass some simple Python scripting with ‘pyshark’, ‘python-nmap’, and ‘impacket’, in order to further parse packets for human-readability. If so, the scripting and analysis of this project will be hosted on Github and can be publicly accessible upon the completion of the project with in-depth documentation and measurements.

## Phase 1 (Computer View)
In this phase, our team will focus on capturing WiFi traffic originating from an Amazon Echo device within the range of the monitoring computer. The goal is to analyze what the Amazon Echo sends out and receives upon activation of different voice commands, song requests, and other interactions. To achieve this, we will use Wireshark to capture WLAN traffic from the Echo device.

### Methodology
1. Launch Wireshark and configure it to capture packets on the WLAN interface.
2. Start monitoring for WiFi traffic.
3. Activate various voice commands and interactions with the Amazon Echo device.
4. Capture and analyze the packets exchanged during these interactions.
5. Examine the packets to understand the nature of the data being sent and received.

### Expected Findings
We anticipate capturing HTTPS-encrypted traffic between the Amazon Echo device and external Amazon servers. The findings will reveal how often the Echo device communicates with Amazon servers and what type of data is exchanged. This information is crucial for understanding the behavior of the device and its interaction with the cloud.

## Phase 2 (Router View)
W.I.P.

## Extra Findings
- SSDP packets are essentially "hello" messages from the Alexa device to inform other devices on the network that it's available for interaction and to provide information about its capabilities and services.  it helps devices like your computer or mobile phone discover and interact with the Alexa device for voice commands and other interactions.

- Wireshark can only see packets passing through the interface it's bound to, so if you're running it on the wireless interface of your laptop (for example) you'll only see packets intended for your laptop or broadcast packets on your LAN meant for everyone. You may be able to put your laptop's wifi interface into promiscuous mode and see all wifi traffic, this will be dependent on the drivers and OS of your device

- While most of the traffic to and from the Amazon Echo will be encrypted over HTTPS, Wireshark will still provide insights into the volume and types of traffic flowing to and from different locations. Additionally, you may observe protocols like Bonjour/SSDP and DHCP, which could offer interesting insights into device discovery and network interactions.

## Conclusion
In conclusion, this project aims to shed light on the network behavior of the Amazon Echo device. By capturing and analyzing Wi-Fi traffic during various interactions and voice commands, we can gain a better understanding of how the device communicates with external servers and what type of data is exchanged. This information is essential for privacy and security considerations and can help users make informed decisions regarding their smart home devices.


## Screenshots

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

## Run Locally

Clone the project

```bash
  git clone https://https://github.com/aidanvancil/alexa_recon.git
```

Go to the project directory

```bash
  cd alexa_recon
```

Install dependencies

```bash
  pip install -r requirements.txt
```

Run Program

```bash
  python3 capture_packets.py <file>
```


## Resources Used

- [Wireshark](https://www.wireshark.org/): Official website for Wireshark, a widely-used network protocol analyzer.

- [pyshark](https://github.com/KimiNewt/pyshark): The official GitHub repository for the pyshark library, which is used for packet analysis with Python.

- [nmap](https://nmap.org/): The official website for Nmap, a popular open-source network scanning tool.

- [Burp Suite](https://portswigger.net/burp): Burp Suite is a cybersecurity tool used for web application security, but it can


## Authors
- Moises Moreno
- Foster Schmidt
- Aidan Vancil
