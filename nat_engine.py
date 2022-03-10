from scapy.layers.inet import TCP, IP
from ipaddress import IPv4Interface, IPv4Address, ip_network
from ip_and_port import IpAndPort
from nat_table import NatTable, NatEntry
from scapy.all import sniff, send
import random
import netifaces
from threading import Thread

class NatEngine:

    _outside_iface: str
    _outside_ip: IPv4Interface
    _outside_ip: IPv4Address

    _inside_iface: str
    _inside_net: IPv4Interface
    _inside_ip: IPv4Address

    _nat_table: NatTable

    _ephemeral_port_range = range(32768, 60999)
    _used_ports = set()

    def __init__(self, 
        inside_interface_name: str,
        outside_interface_name: str) -> None:

        self._nat_table = NatTable()
        
        self._inside_iface = inside_interface_name
        inside_iface = netifaces.ifaddresses(inside_interface_name)[netifaces.AF_INET][0]
        self._inside_ip = IPv4Address(inside_iface['addr'])
        self._inside_net = ip_network(f"{self._inside_ip}/{inside_iface['netmask']}", strict=False)
        
        self._outside_iface = outside_interface_name
        outside_iface = netifaces.ifaddresses(outside_interface_name)[netifaces.AF_INET][0]
        self._outside_ip = IPv4Address(outside_iface['addr'])
        self._outside_net = ip_network(f"{self._outside_ip}/{outside_iface['netmask']}", strict=False)   

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
            

    def _handle_inside_packet(self, packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        print(f"O Inside Packet: {packet.summary()}")

        src_inside = IpAndPort(IPv4Address(packet[IP].src), packet[TCP].sport)
        dst = IpAndPort(IPv4Address(packet[IP].dst),packet[TCP].dport)
            
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


        print(f"N Inside Packet: {new_ip_packet.summary()}")

        send(new_ip_packet, verbose=False)



    def _handle_outside_packet(self, packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        local_outside = IpAndPort(IPv4Address(packet[IP].dst),packet[TCP].dport)
          
        nat_entry = self._nat_table.get_entry_by_outside_ip_and_port(local_outside)

        if nat_entry != None:    
            print(f"O Outside Packet: {packet.summary()}")

            new_ip_packet=IP(
                src=packet[IP].src,
                dst=str(nat_entry.source_inside.ip),
                ttl=packet[IP].ttl) / packet[TCP]

            new_ip_packet[TCP].dport = nat_entry.source_inside.port

            new_ip_packet[TCP].chksum = None

            print(f"N Outside Packet: {new_ip_packet.summary()}")

            send(new_ip_packet, verbose=False)
    

    def start(self):
        print(f"Outside Iface:   {self._outside_iface}")
        print(f"Outside IP:      {self._outside_ip}")
        print(f"Outside Network: {self._outside_net}")

        print(f"Inside Iface:    {self._inside_iface}")
        print(f"Inside IP:       {self._inside_ip}")
        print(f"Inside Network:  {self._inside_net}")
        
        outside_sniffer = Sniffer(
            self._outside_iface, 
            self._outside_ip, 
            self._handle_outside_packet)
        outside_sniffer.start()

        inside_sniffer = Sniffer(
            self._inside_iface, 
            self._inside_ip, 
            self._handle_inside_packet)
        inside_sniffer.start()

       


class Sniffer(Thread):
    def  __init__(self, interface, ip, prn):
        super().__init__()

        self.interface = interface
        self.ip = ip
        self.prn = prn

    def run(self):
        sniff(iface=self.interface, 
              filter=f"not src host {self.ip}", 
              prn=self.prn)