###############################################################################
# (c) 2022 Michael MacFadden
#
# CSC-841 Cyber Operations II
# Lab 08 and 09
###############################################################################

from scapy.layers.inet import TCP, IP
from ipaddress import IPv4Interface, IPv4Address, ip_network
from ip_and_port import IpAndPort
from nat_table import NatTable, NatEntry, TcpSession
from scapy.all import sniff, send
import random
import netifaces
from threading import Thread, Lock
import time

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

class NatEngine:

    _outside_iface: str
    _outside_ip: IPv4Interface
    _outside_ip: IPv4Address
    _outside_mac: str

    _inside_iface: str
    _inside_net: IPv4Interface
    _inside_ip: IPv4Address
    _inside_mac: str

    _nat_table: NatTable
    _nat_table_lock: Lock = Lock()

    _ephemeral_port_range = range(32768, 60999)
    _used_ports = set()

    _verbose: bool

    def __init__(self, 
        inside_interface_name: str,
        outside_interface_name: str,
        verbose: bool) -> None:

        self._verbose = verbose

        self._nat_table = NatTable()
        
        self._inside_iface = inside_interface_name
        inside_iface = netifaces.ifaddresses(inside_interface_name)[netifaces.AF_INET][0]
        self._inside_ip = IPv4Address(inside_iface['addr'])
        self._inside_net = ip_network(f"{self._inside_ip}/{inside_iface['netmask']}", strict=False)
        self._inside_mac = netifaces.ifaddresses(inside_interface_name)[netifaces.AF_LINK][0]["addr"]

        self._outside_iface = outside_interface_name
        outside_iface = netifaces.ifaddresses(outside_interface_name)[netifaces.AF_INET][0]
        self._outside_ip = IPv4Address(outside_iface['addr'])
        self._outside_net = ip_network(f"{self._outside_ip}/{outside_iface['netmask']}", strict=False)   
        self._outside_mac = netifaces.ifaddresses(outside_interface_name)[netifaces.AF_LINK][0]["addr"]


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

        if self._verbose:
            print(f"Rx Inside Packet: {packet.summary()}")

        src_inside = IpAndPort(IPv4Address(packet[IP].src), packet[TCP].sport)
        dst = IpAndPort(IPv4Address(packet[IP].dst),packet[TCP].dport)
            
        nat_entry = self._nat_table.get_entry_by_inside_ip_and_port(src_inside)

        if nat_entry == None:
            outside_port = self.get_ephemeral_port()
            src_outside = IpAndPort(self._outside_ip, outside_port)
     
            nat_entry = NatEntry(
                src_inside, src_outside, dst, time.monotonic(), TcpSession())

            self._nat_table.add_entry(nat_entry)
        else:
            seq = packet[TCP].seq
            if nat_entry.tcp_session_state.outside_fin_seq_no == packet[TCP].ack - 1 and packet[TCP].flags & ACK:
                nat_entry.tcp_session_state.outside_fin_acked = True
                if self._verbose:
                    print (f"Outside TCP FIN ACK sent.")

            if packet[TCP].flags & FIN:
                nat_entry.tcp_session_state.inside_fin_seq_no = seq
                if self._verbose:
                    print (f"Inside TCP FIN sent with seq {packet[TCP].seq}")
            
        new_ip_packet=IP(
            src=str(nat_entry.source_outside.ip),
            dst=packet[IP].dst,
            ttl=packet[IP].ttl) / packet[TCP]

        new_ip_packet[TCP].sport = nat_entry.source_outside.port

        new_ip_packet[TCP].chksum = None

        if self._verbose:
            print(f"Tx Inside Packet: {new_ip_packet.summary()}")

        send(new_ip_packet, verbose=False)

        self._handle_tcp_session_state(nat_entry)


    def _handle_outside_packet(self, packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        local_outside = IpAndPort(IPv4Address(packet[IP].dst),packet[TCP].dport)
          
        nat_entry = self._nat_table.get_entry_by_outside_ip_and_port(local_outside)

        if nat_entry != None: 
            seq = packet[TCP].seq

            if self._verbose:   
                print(f"Rx Outside Packet: {packet.summary()}")

            if nat_entry.tcp_session_state.inside_fin_seq_no == packet[TCP].ack - 1 and packet[TCP].flags & ACK:
                nat_entry.tcp_session_state.inside_fin_acked = True
                if self._verbose:
                    print (f"Inside TCP FIN ACK received.")
            
            if packet[TCP].flags & FIN:
                nat_entry.tcp_session_state.outside_fin_seq_no = seq
                if self._verbose:
                    print (f"Outside TCP FIN received with seq {packet[TCP].seq}")

            new_ip_packet=IP(
                src=packet[IP].src,
                dst=str(nat_entry.source_inside.ip),
                ttl=packet[IP].ttl) / packet[TCP]

            new_ip_packet[TCP].dport = nat_entry.source_inside.port

            new_ip_packet[TCP].chksum = None

            if self._verbose:
                print(f"Tx Outside Packet: {new_ip_packet.summary()}")

            send(new_ip_packet, verbose=False)

            self._handle_tcp_session_state(nat_entry)
        else:
            print(f"Er Outside Packet: {packet.summary()}")
    

    def _handle_tcp_session_state(self, entry: NatEntry) -> None:
        if entry.tcp_session_state.inside_fin_acked and entry.tcp_session_state.outside_fin_acked:
            with self._nat_table_lock:
                if self._nat_table.has_entry(entry):
                    if self._verbose:
                        print("TCP close completed, removing NAT mapping")
                    self._nat_table.remove_entry(entry)
        

    def start(self):
        print("Nat Engine Starting\n")

        print(f"  Outside Iface:   {self._outside_iface} ({self._outside_mac})")
        print(f"  Outside IP:      {self._outside_ip}")
        print(f"  Outside Network: {self._outside_net}\n")

        print(f"  Inside Iface:    {self._inside_iface} ({self._inside_mac})")
        print(f"  Inside IP:       {self._inside_ip}")
        print(f"  Inside Network:  {self._inside_net}\n")
        
        outside_sniffer = FilteredPacketSniffterThread(
            self._outside_iface, 
            self._outside_mac, 
            self._handle_outside_packet)
        outside_sniffer.start()

        inside_sniffer = FilteredPacketSniffterThread(
            self._inside_iface, 
            self._inside_mac, 
            self._handle_inside_packet)
        inside_sniffer.start()

        print("Nat Engine Started\n")
        print("Press CTRL-C to quit.")

        inside_sniffer.join()

       
class FilteredPacketSniffterThread(Thread):
    def  __init__(self, interface, mac, prn):
        super().__init__()

        self.interface = interface
        self.mac = mac
        self.prn = prn
        self.setDaemon(True)

    def run(self):
        sniff(iface=self.interface, 
              filter=f"not ether src host {self.mac}", 
              prn=self.prn)