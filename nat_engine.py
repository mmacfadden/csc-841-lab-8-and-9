from scapy.layers.inet import TCP, IP
from ipaddress import IPv4Interface, IPv4Address, ip_network
from ip_and_port import IpAndPort
from nat_table import NatTable, NatEntry
from scapy.all import sniff, send
import random

class NatEngine:

    __private_net: IPv4Interface
    _ephemeral_port_range = range(32768, 60999)

    _used_ports = set()

    _outside_ip: IPv4Address

    _nat_table: NatTable

    def __init__(self, 
        private_network: str,
        outside_ip: str) -> None:

        self._nat_table = NatTable()

        self._outside_ip = IPv4Address(outside_ip)
        self.__private_net = ip_network(private_network)


    def __get_inside_and_outside_pair(self, addr1, addr2):
        if (addr1.ip in self.__private_net):
            return (addr1, addr2)
        elif (addr2.ip in self.__private_net): 
            return (addr2, addr1)
        else:
            raise "Neither address is in the private network"


    def get_ephemeral_port(self) -> int:
        port = random.randint(
            self._ephemeral_port_range.start, 
            self._ephemeral_port_range.stop)
        while(port in self._used_ports):
            port = random.randint(
                self._ephemeral_port_range.start, 
                self._ephemeral_port_range.stop)
        
        self._used_ports.add(port)

        return port

    def process_ip_packet(self, packet):
        ip_packet: IP = packet.getlayer(IP)
        
        if (packet.haslayer(TCP)):
            tcp_packet: TCP = packet.getlayer(TCP)
            
            src_addr = IpAndPort(
                IPv4Address(ip_packet.src), 
                tcp_packet.sport)

            dest_addr = IpAndPort(
                IPv4Address(ip_packet.dst),
                tcp_packet.dport)
            
            (inside, outside) = self.__get_inside_and_outside_pair(src_addr, dest_addr)

            if (src_addr == inside):
                self.process_outgoing_packet( packet, inside, outside)            
            else:
                self.process_incomming_packet( packet, inside, outside)            
            


    def process_outgoing_packet(self, packet, src_inside: IpAndPort, dst: IpAndPort):
        print(f"O Out: {packet.summary()}")

        nat_entry = self._nat_table.get_entry_by_inside_ip_and_port(src_inside)

        if nat_entry == None:
            outside_port = self.get_ephemeral_port()
            src_outside = IpAndPort(self._outside_ip, outside_port)
            nat_entry = NatEntry(src_inside, src_outside, dst)
            self._nat_table.add_entry(nat_entry)
       
            
        new_ip_packet=IP(
            src=str(nat_entry.source_outside.ip),
            dst=packet[IP].dst,
            ttl=packet[IP].ttl) / packet[TCP]

        new_ip_packet[TCP].sport = nat_entry.source_outside.port

        new_ip_packet[TCP].chksum = None


        print(f"N Out: {new_ip_packet.summary()}")

        send(new_ip_packet)



    def process_incomming_packet(self, packet, local_outside, remote):
        nat_entry = self._nat_table.get_entry_by_outside_ip_and_port(local_outside)

        if nat_entry != None:    
            print(f"O In: {packet.summary()}")

            new_ip_packet=IP(
                src=packet[IP].src,
                dst=str(nat_entry.source_inside.ip),
                ttl=packet[IP].ttl) / packet[TCP]

            new_ip_packet[TCP].dport = nat_entry.source_inside.port

            new_ip_packet[TCP].chksum = None

            print(f"N In: {new_ip_packet.summary()}")

            send(new_ip_packet)


    def packet_handler(self, packet):
        if (packet.haslayer(IP)):
            self.process_ip_packet(packet)

    def start(self):
        print(f"private network: {self.__private_net}")
        sniff(iface="eth0", 
              filter="not src host 172.16.103.129", 
              prn=self.packet_handler)