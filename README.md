
# Alexa Reconnaissance

## Abstract 
text here.

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
  git clone https://link-to-project
```

Go to the project directory

```bash
  cd my-project
```

Install dependencies

```bash
  npm install
```

Start the server

```bash
  npm run start
```


## Resources Used

 - [Awesome Readme Templates](https://awesomeopensource.com/project/elangosundar/awesome-README-templates)
 - [Awesome README](https://github.com/matiassingers/awesome-readme)
 - [How to write a Good readme](https://bulldogjob.com/news/449-how-to-write-a-good-readme-for-your-github-project)

## Authors
- Moises Moreno
- Foster Schmidt
- Aidan Vancil
