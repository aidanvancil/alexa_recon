
# Alexa Reconnaissance

## Abstract 
In this project, our team will demonstrate what the Amazon Echo sends out and receives upon activation of different voice assertions. As a stretch goal we will focus on the same analysis for when the Amazon Echo pairs with Bluetooth devices. Our team presumes the Echo is already encrypted with HTTPS during transit and TLS at rest, so we will utilize Burp Suite, a tool used for packet analysis in combination with Wireshark. Understandably so, capturing WiFi traffic can be difficult, so our team will specifically take Wireshark WLAN capturing in mind. The analysis performed will be on the average latency and the different packets being sent out to the external Amazon server upon varied voice assertions or song requests upon pairing with a Bluetooth device. It will be our focus to see how often the Echo is listening in to hear for an assertion and so on. It is possible this project might encompass some simple Python scripting with ‘pyshark’, ‘python-nmap’, and ‘impacket’, in order to further parse packets for human-readability. If so, the scripting and analysis of this project will be hosted on Github and can be publicly accessible upon the completion of the project with in-depth documentation and measurements.

## Phase 1 (Computer View)
text here.

## Phase 2 (Router View)
text here.

## Extra Findings
SSDP packets are essentially "hello" messages from the Alexa device to inform other devices on the network that it's available for interaction and to provide information about its capabilities and services.  it helps devices like your computer or mobile phone discover and interact with the Alexa device for voice commands and other interactions.

Wireshark can only see packets passing through the interface it's bound to, so if you're running it on the wireless interface of your laptop (for example) you'll only see packets intended for your laptop or broadcast packets on your LAN meant for everyone. You may be able to put your laptop's wifi interface into promiscuous mode and see all wifi traffic, this will be dependent on the drivers and OS of your device

almost all the traffic to and from the Echo will be encrypted over https. You'll be able to see how much traffic is flowing to and from different locations and other stuff like Bonjour/SSDP and DHCP which may be interesting

## Conclusion
text here.

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

 - [Awesome Readme Templates](https://awesomeopensource.com/project/elangosundar/awesome-README-templates)
 - [Awesome README](https://github.com/matiassingers/awesome-readme)
 - [How to write a Good readme](https://bulldogjob.com/news/449-how-to-write-a-good-readme-for-your-github-project)

## Authors
- Moises Moreno
- Foster Schmidt
- Aidan Vancil
