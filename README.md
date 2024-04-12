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

There is a bit more information within the packet and its header that is accessible in the code, but I've decided not to include the payload data because it is unreadable without decryption, and the header length because it does not provide useful information. I've left printouts commented out in case during further development I choose to expand the scope of the details provided.

I used the gtk toolkit to create a simple GUI in C to display this data because it is a free/open source project that met my needs. I have previously made web-apps before and wanted to create a project that isn't another CRUD app.
I used the libpcap library to leverage the pcap interface in order to capture packets and extract their details.
I also used Github Copilot to help debug linker and PATH issues, explain unfamiliar shell commands and library functionality, and even to fill in repetitive boilerplate logic. 
