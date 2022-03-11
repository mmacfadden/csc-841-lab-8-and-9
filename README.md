# DSU CSC-841 Lab 08 ad 09
This project contains my implementation of Lab 8 and 9 for Dakota State University CSC-841 Cyber Operations II for the Spring 2022 Semester.

The code implements a basic [network address translation](https://en.wikipedia.org/wiki/Network_address_translation)(NAT) server.  The server implments a Symmetric NAT approach for source nat (SNAT).

## Dependencies
This project was developed with the following dependencies:
* Python: 3.9.1
* Scapy:  2.4.4

## Usage

TBD

## Linux TCP Stack Configuration
The Linux kernel runs the TCP stack. When it recieves packets on the network it will check to see if the related port is open, by the kernel.  If it is not it will reply with a TCP RST packet.

Even though we use scapy to sniff the traffic and handle the packet, scapy is running in user space, and the tcp stack is running in the kernal, unaware of what our nat server is doing.  Thus it will reply to the sender with the RST packet and interrupt the TCP handsake.

To account for this we use IPTABLES(8) to drop the RST packets.

```shell
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 172.16.149.1 -j DROP
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.200.1 -j DROP
```