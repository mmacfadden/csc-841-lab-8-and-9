# DSU CSC-841 Lab 08 ad 09
This project contains my implementation of Lab 8 and 9 for Dakota State University CSC-841 Cyber Operations II for the Spring 2022 Semester.

## Functionality
The code implements a basic [network address translation](https://en.wikipedia.org/wiki/Network_address_translation)(NAT) server.  The server implments a Symmetric NAT approach for source nat (SNAT).  The server will bind to two network interfaces. The first is the inside interface which is connected to the private address space.  The second is the outside interface which will connect to the "public" interface.  The entire inside interface is proxied (e.g. all ports). The outside and inside interfaces may not be the same.

The server has the following functionality:
* Both TCP and UDP are supported for IPv4.
* ICMP Destination Unreachable packets for valid TCP / UDP flows are forwarded from the outside interface to the inside interface.
* When a packet is received on the inside interface for a new source IP/Port and destination IP/Port pair a new ephemeral port on the outside interface is chosen.
* The server will then manipulate the packet to use the outside interface's IP and the chosen outside ephemeral port as the source, and then resend the packet on the outside interface.
* When a packet is received on the outside interface that corresponds to an active ephemral port and is from the correct IP/Port the server will modify the desitation IP/Port of the packet to match the inside host that initiated the exchange.
* Packets received on the outside interface on a non-active ephemeral port will be dropped.
* Packets received on the outside interface on an active ephemeral port, but from a different IP/Port than the connection was initiated on will be dropped.
* When the TCP connection is properly closed (e.g. bidirectional FIN-ACK exchanges or RST packets are received), the ephemeral port will be released and the NAT mapping will purged of that flow.
* The NAT server keeps track of the last time a packet was sent or received via an existing NAT mapping and periodically checks for idle connections that have not been used in a while.  Stale connections will be removed.  Both the idle time and the idle check interval are configurable.
* The system does a reasonable attempt to validate input arguments to ensure that the specified interfaces exist in the system, and that other settings are sensible.


## Dependencies
This project was developed with the following dependencies:
* Python: 3.9.1
* Scapy:  2.4.4

## Source Code
* [nat-server.py](nat-server.py) file is an executable python scrtip and is the main entrypoint for running the server.
* [natengine](natengine): The natengine director is a python module containing the majority of the NAT logic.

## Installation
To install dependencies:

```shell
pip install -r requirements.txt
```

## Usage
To run the server use the `nat.py` script.  Make sure it is executable and that you have the python3 binary on your path. You must specifcy the inside and outside network interfaces to use.  An example command might look like this:

```shell
./nat-server.py eth1 eth2
```

You can see all help options by using "nat-server.py -h".  The output is below:

```shell
usage: nat-server.py [-h] [-i seconds] [-c seconds] [-v] inside outside

A simple NAT Server.

positional arguments:
  inside                The interface name of the inside netwrok interface
  outside               The interface name of the outside netwrok interface

optional arguments:
  -h, --help            show this help message and exit
  -i seconds, --idle-timeout seconds
                        The number of seconds after which a connection is assumed to have timed out.
  -c seconds, --idle-check-interval seconds
                        How often idel connections should be scanned for.
  -v, --verbose         Print additional information
```

## Linux TCP Stack Configuration
The Linux kernel runs the TCP stack. When it recieves packets on the network it will check to see if the related port is open, by the kernel.  If it is not it will reply with a TCP RST packet.

Even though we use scapy to sniff the traffic and handle the packet, scapy is running in user space, and the tcp stack is running in the kernal, unaware of what our nat server is doing.  Thus it will reply to the sender with the RST packet and interrupt the TCP handsake.

To account for this we use IPTABLES(8) to drop the RST packets.

```shell
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <inside-interface-ip> -j DROP
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <outside-interface-ip> -j DROP
```

Similarly, when a UDP packet arrives at the outside interface (on an active flow), the Linux Kernel will reply with an ICPM Destination Unreachable packet. This will cause tools like netcat to assume the connection has been refused.  We can use IPTABLES to block these packets as well:

```shell
iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -s <outside-intrface-ip> -j DROP
```

## License
The code is licensed under the MIT License. The text of the license can be found in the [License](License) file.