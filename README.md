# Juans-Packet-Sniffer
My final project for CS50: a packet sniffer with a GUI coded in C.

![image](https://github.com/JuanOfMany/Juans-Packet-Sniffer/assets/101835485/a5ae300a-25ac-4047-812a-293816cba469)

I chose to create a simple packet sniffer MVP as my final project in order to better solidify my grasp of C and learn about networking and the internet.

As of the date of writing this, my project is an executable program that scrapes a hard-coded number of packets on the en0 network interface (wifi for modern Macbooks) and displays some of the packet data in a minimal GUI.

The packet data presented includes: 
* packet Id
* Time Sniffed
* IP Version
* Source IP
* Destination IP
* Checksum value
* Time to Live

The usefulness of this project is dependent on the environment in which it is run. When run on a regular computer it does capture and display packet data, but those packets are being transported from the computer to a router and vice versa. This means that the source and destination IP addresses aren't very useful.
This program is actually useful when run on a server or router (which must be put into "Monitor Mode") that handles any traffic that you want to monitor. These use cases could allow you to detect DDOS attacks, or unauthorized access to your network that you would otherwise have not known about... unless you use Wireshark, which is a free and open source packet analysis tool that I was vaguely inspired by to make this project. 
Using the source IP information along with a geolocation API can allow you to pinpoint new, unwanted, or just strange traffic on your network. This could also be used to check if someone is using a well-documented VPN, which may or may not be indicative of breaking Terms of Service agreements or nefarious activities.

There is a bit more information within the packet and its header that is accessible in commented out code, but I've decided not to include them for the following reasons:
Payload Data: It is unreadable without decryption, and the header length because it does not provide useful information. I've left printouts commented out in case during further development I choose to expand the scope of the details provided.
Header Length: Not useful information, as invalid header lengths lead to packets being rejected. 

I used the gtk toolkit to create a simple GUI in C to display this data because it is a free/open source project that met my needs. I have previously made web-apps before and wanted to create a project that isn't another CRUD app.
I used the libpcap library to leverage the pcap interface in order to capture packets and extract their details.
I also used Github Copilot to help debug linker and PATH issues, explain unfamiliar shell commands and library functionality, and even to fill in repetitive boilerplate logic. 

I had stretch goals that I wasn't able to meet in time for this submission, but plan to continue development to add:
* Make app a conventional "tile app" on MacOS and Windows
* Add an open-source logo to app
* Allow for user input to start packet capture
  * Start capturing button
  * User input for length of scan in seconds
  * User input for max number of packets to scan for
  * User input for continuous scanning mode
