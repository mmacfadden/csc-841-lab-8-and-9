# DSU CSC-841 Lab 08 ad 09


## Linux TCP Stack Workaround
The Linux kernel runs the TCP stack. When it recieves packets on the network it will check to see if the related port is open, by the kernel.  If it is not it will reply with a TCP RST packet.

Even though we use scapy to sniff the traffic and handle the packet, scapy is running in user space, and the tcp stack is running in the kernal, unaware of what our nat server is doing.  Thus it will reply to the sender with the RST packet and interrupt the TCP handsake.

To account for this we use IPTABLES(8) to drop the RST packets.

```shell
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 172.16.103.129 -j DROP
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.200.1 -j DROP
```