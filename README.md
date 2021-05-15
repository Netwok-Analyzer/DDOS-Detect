# Network Packet Analyzer


![dos](https://user-images.githubusercontent.com/60442308/117463729-9c174980-af6d-11eb-846c-2f96b4cdc932.png)

Network traffic or data traffic is the amount of data moving across a network at a given point of time. It is best practise to monitor and log this traffic, as it helps us see what goes in and out of our network, makes it more visible to us in a way.
Network Traffic Analysis(NTA) is monitoring network availability and activity to identify anomalies, including security and operational issues and it allows the organisation to detect attacks at an early stage, and effectively isolate threats. Each association, either enormous or little, faces difficulties to survive and dealing with the data.
Attacks like DDOS cause lots of damage to the organisation Interrupting their workflow. Therefore using a detection tool for any cyber attack is a good practice.**Network packet analyzer(i.e DOS-Detect)** is a tool that analyze the captured data packets on a network then present us in an understandable form.

The project aims to create a network packet analyser tool, capable of automating various analytical steps during DFIR phase of a Cyber Incident.
This tool has been created keeping 2 objective in mind:
- To parse logged network packets and automate the passive analysis of the traffic to an extent.
- Differentiate basic traffic from reconnaissance traffic containing exploits, or malicious intent.

Here's  the functionalities that the tool includes:
- Parsing the network packets
- Geolocate the traffic from source to destination
- Map the geolocated IP on google earth
- Detecting cyber attack [supports: DDOS]


# Deep Dive into the Tool

### Parsing the Network Packets

This is the first step that needs to be done in order to get detail view of every data packet of the pcap file.In this step we use the python inbuilt library [dpkt](https://dpkt.readthedocs.io/en/latest/) to parse the data packets and get into the every section of the data frame (i.e IP data, TCP data and many more)

## Geolocate the traffic from source to destination
This includes getting the Geolocation of source IP  and destination IP of every data packet that is present in the pcap file. Here we get the IP data from the Ethernet frame and then get the information about the source and destination addresses.In this step we used [maxmind](https://www.maxmind.com/en/home) database to get the geoloaction of IP and [geoip2](https://pypi.org/project/geoip2/) library to handle the maxmind database and the infamous socket library to get the IPv4 form of IP address.

## Map the geolocated IP on google earth
Here we provide ease to the user by getting the visulisation of the IP addresses on the google earth by getting a .kml file as the output. 

## Detecting the DDOS attack
It is the last and the major functionality of the tool. So distributed denial-of-service [DDOS](https://www.cloudflare.com/en-in/learning/ddos/what-is-a-ddos-attack/) is a malicious attempt to disrupt the normal traffic of a targeted server, service or network by overwhelming the target or its surrounding infrastructure with a flood of Internet traffic. For detectiing this type of major attack we are taking 3 factors into consideration that can confirm us that a DDOS has been performed:
- [LOIC](https://www.wallarm.com/what/what-is-low-orbit-ion-cannon-loic) Download by the attacker
- [Hivemind](https://www.wallarm.com/what/what-is-low-orbit-ion-cannon-loic) issued by the attacker
- No of packets sent by the attcaker

Here we get into the TCP section of the IP and gets the data to see the HTTP header for confiramtion of the LOIC download and then we look for port 6667 i.e used by IRCservers for performing DDOS and get the command and next we get the count of the packets.
This is done by utilizing the dpkt and socket library

# Demo of the tool
Here's the live demo of the tool you can see:

https://user-images.githubusercontent.com/60442308/118368175-4ff88480-b5bf-11eb-9e99-dab52f5b626e.mp4





# Usage

- Clone the repository

      $ git clone https://github.com/Netwok-Analyzer/Network-Packet-Analyzer.git

- Install necessary libraries required(python3+)

      $ pip3 install -r requirements.txt

- Run the rool 
       
      cd  Network-Packet-Analyzer/
      python Geoprint.py -h

- Output you get

      usage: Geoprint.py [-h] -l PCAP [-p] [-g] [-d]
      optional arguments:
       -h, --help  show this help message and exit
       -l PCAP     Add the pcap file location
       -p          print the geolocation of the IP addresses
       -g          Want a Kml file to see on google earth?
       -d          Check for the DOS attack


