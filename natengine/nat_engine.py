###############################################################################
# (c) 2022 Michael MacFadden
#
# CSC-841 Cyber Operations II
# Lab 08 and 09
###############################################################################

from scapy.layers.inet import TCP, IP, UDP, ICMP, UDPerror, TCPerror, IPerror
from scapy.all import sniff, send
import random
import netifaces
from ipaddress import IPv4Address, ip_network
from threading import Thread, Lock
import time

from .interval_timer import IntervalTimer
from .ip_and_port import IpAndPort
from .tcp_flags import TcpFlags
from .nat_table import NatTable, NatEntry, TcpSession




class NatEngine:
    """Implements the main NAT Gateway routing logic.

    This class leverages scapy to listen to packets on an outside and inside
    network interface, mutates, and fowards them to implement a Symmetric, Source
    NAT approach.

    The class supports TCP/IP and UDP/IP protocols for IPv4.
    """
    def __init__(self, 
        inside_interface_name: str,
        outside_interface_name: str,
        idle_timeout_s: int,
        idle_check_interval_s: int,
        verbose: bool) -> None:

        self._verbose = verbose
        self._idle_timeout_s = idle_timeout_s
        self._idle_check_interval_s = idle_check_interval_s

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

        self._used_ports = set()
        self._ephemeral_port_range = range(32768, 60999)
        self._nat_table_lock: Lock = Lock()

    def start(self):
        """The main entrypoint method for the NATEngine class that starts the server.
        
        This method will start monitoring for traffic on the specified interfaces and
        forward traffic as appropriate.
        """
        print("Nat Engine Starting\n")

        print(f"  Outside Iface:   {self._outside_iface} ({self._outside_mac})")
        print(f"  Outside IP:      {self._outside_ip}")
        print(f"  Outside Network: {self._outside_net}\n")

        print(f"  Inside Iface:    {self._inside_iface} ({self._inside_mac})")
        print(f"  Inside IP:       {self._inside_ip}")
        print(f"  Inside Network:  {self._inside_net}\n")
        
        self._timeout_timer = IntervalTimer(
            "Timeout Timer", self._check_for_idle_timeouts, self._idle_check_interval_s)
        self._timeout_timer.start()

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
 
            
    ##
    ## Inside Packet Handling
    ##

    def _handle_inside_packet(self, packet):
        if not packet.haslayer(IP):
            return

        self._verbose_log(f"Rx Inside Packet: {packet.summary()}")

        sport = self._get_port_from_packet(packet, True)
        dport = self._get_port_from_packet(packet, False)

        src_inside = IpAndPort(IPv4Address(packet[IP].src), sport)
        dst = IpAndPort(IPv4Address(packet[IP].dst), dport)
            
        nat_entry = self._nat_table.get_entry_by_inside_ip_and_port(src_inside)

        if nat_entry == None:
            outside_port = self._get_ephemeral_outside_port()
            src_outside = IpAndPort(self._outside_ip, outside_port)
     
            nat_entry = NatEntry(
                src_inside, src_outside, dst, time.monotonic(), TcpSession())

            self._nat_table.add_entry(nat_entry)

        payload = self._handle_inside_payload(packet, nat_entry)

        nat_entry.last_packet_time = time.monotonic()
            
        new_ip_packet=IP(
            src=str(nat_entry.source_outside.ip),
            dst=packet[IP].dst,
            ttl=packet[IP].ttl) / payload       

        self._verbose_log(f"Tx Inside Packet: {new_ip_packet.summary()}")

        send(new_ip_packet, verbose=False)


    def _handle_inside_payload(self, packet: any, nat_entry: NatEntry) -> any:
        if packet.haslayer(TCP):
            return self._handle_inside_tcp_payload(packet, nat_entry)
        elif packet.haslayer(UDP):
            return self._handle_inside_udp_payload(packet, nat_entry)
        else:
            raise Exception("The only protocols supported are TCP/IP and UDP/IP")


    def _handle_inside_tcp_payload(self, packet: any, nat_entry: NatEntry) -> any:
        tcp_layer = packet[TCP].copy()
        seq = tcp_layer.seq

        if nat_entry.tcp_session_state.outside_fin_seq_no == tcp_layer.ack - 1 and tcp_layer.flags & TcpFlags.ACK:
            nat_entry.tcp_session_state.outside_fin_acked = True
            self._verbose_log(f"Outside TCP FIN ACK sent.")

        if tcp_layer.flags & TcpFlags.FIN:
            nat_entry.tcp_session_state.inside_fin_seq_no = seq
            self._verbose_log(f"Inside TCP FIN sent with seq {seq}")

        if tcp_layer.flags & TcpFlags.RST:
            nat_entry.tcp_session_state.reset_recieved = True
            self._verbose_log("Inside TCP RST received with")
    
        tcp_layer.sport = nat_entry.source_outside.port
        tcp_layer.chksum = None

        self._handle_tcp_session_state(nat_entry)

        return tcp_layer
    

    def _handle_inside_udp_payload(self, packet: any, nat_entry: NatEntry) -> any:
        udp_layer = packet[UDP].copy()
        
        udp_layer.sport = nat_entry.source_outside.port
        udp_layer.chksum = None
    
        return udp_layer


    ##
    ## Outside Packet Handling
    ##
    def _handle_outside_packet(self, packet):
        if not packet.haslayer(IP):
            return

        dport = self._get_port_from_packet(packet, False)
        sport = self._get_port_from_packet(packet, True)

        local_outside = IpAndPort(IPv4Address(packet[IP].dst), dport)
        nat_entry = self._nat_table.get_entry_by_outside_ip_and_port(local_outside)

        if nat_entry != None:
            from_ip_and_port = IpAndPort(IPv4Address(packet[IP].src), sport) 
            correct_rremote_ip_and_port = from_ip_and_port == nat_entry.dest_outside

            if correct_rremote_ip_and_port:
                self._handle_valid_outside_packet(packet, nat_entry)
            else:
                self._handle_invalid_outside_packet(packet)

        else:
            self._handle_invalid_outside_packet(packet)


    def _handle_invalid_outside_packet(self, packet) -> None:
       self._verbose_log(f"Dropped Outside Packet: {packet.summary()}")


    def _handle_valid_outside_packet(self, packet, nat_entry: NatEntry) -> None:
        self._verbose_log(f"Rx Outside Packet: {packet.summary()}")

        nat_entry.last_packet_time = time.monotonic()

        payload = self._handle_outside_payload(packet, nat_entry)

        new_ip_packet=IP(
            src=packet[IP].src,
            dst=str(nat_entry.source_inside.ip),
            ttl=packet[IP].ttl) / payload        

        self._verbose_log(f"Tx Outside Packet: {new_ip_packet.summary()}")

        send(new_ip_packet, verbose=False)

    def _handle_outside_payload(self, packet: any, nat_entry: NatEntry) -> any:
        if packet.haslayer(TCP):
            return self._handle_outside_tcp_payload(packet, nat_entry)
        elif packet.haslayer(UDP):
            return self._handle_outside_udp_payload(packet, nat_entry)
        elif packet.haslayer(ICMP):
            return self._handle_outside_icmp_payload(packet, nat_entry)
        else:
            raise Exception("invalid packet")

    def _handle_outside_icmp_payload(self, packet: any, nat_entry: NatEntry) -> any:
        icmp_layer = packet[ICMP].copy()

        if icmp_layer.haslayer(IPerror):
            icmp_layer[IPerror].src = str(nat_entry.source_inside.ip)
            icmp_layer[IPerror].chksum = None
            icmp_layer.chksum = None

        return icmp_layer

    def _handle_outside_tcp_payload(self, packet: any, nat_entry: NatEntry) -> any:
        tcp_layer = packet[TCP].copy()
        seq = tcp_layer.seq

        if nat_entry.tcp_session_state.inside_fin_seq_no == tcp_layer.ack - 1 and tcp_layer.flags & TcpFlags.ACK:
            nat_entry.tcp_session_state.inside_fin_acked = True
            self._verbose_log("Inside TCP FIN ACK received.")
        
        if tcp_layer.flags & TcpFlags.FIN:
            nat_entry.tcp_session_state.outside_fin_seq_no = seq
            self._verbose_log("Outside TCP FIN received with seq {seq}")

        if tcp_layer.flags & TcpFlags.RST:
            nat_entry.tcp_session_state.reset_recieved = True
            self._verbose_log("Outside TCP RST received with")

        self._handle_tcp_session_state(nat_entry)

        tcp_layer.dport = nat_entry.source_inside.port
        tcp_layer.chksum = None

        return tcp_layer


    def _handle_outside_udp_payload(self, packet: any, nat_entry: NatEntry) -> any:
        udp_layer = packet[UDP].copy()
       
        udp_layer.dport = nat_entry.source_inside.port
        udp_layer.chksum = None

        return udp_layer


    ##
    ## Helper Methods
    ##

    def _verbose_log(self, message: str) -> None:
        """A helper method to print a message only if verbose logging is turned on."""
        if (self._verbose):
            print(message)

    def _handle_tcp_session_state(self, entry: NatEntry) -> None:
        """Checks the TCP session state for a NATEntry and removes it if the TCP connection has completed."""
        if ((entry.tcp_session_state.inside_fin_acked and 
            entry.tcp_session_state.outside_fin_acked) or
            entry.tcp_session_state.reset_recieved):
            with self._nat_table_lock:
                if self._nat_table.has_entry(entry):
                    self._verbose_log(f"Removing NAT mapping for {entry.source_inside} > {entry.dest_outside}")
                    self._nat_table.remove_entry(entry)
        

    def _check_for_idle_timeouts(self):
        """Causes the class to check for idle timeouts for ports that can be freed."""
        self._nat_table.remove_timed_out_entries(self._idle_timeout_s)
    
    def _get_ephemeral_outside_port(self) -> int:
        """A helper method to generate and claim an ephemeral port.
        
        This method claims an unused empheral port within the range specified
        at the class level. The port is then marked as in use, so it is not
        re-used.
        """
        port = random.randint(
            self._ephemeral_port_range.start, 
            self._ephemeral_port_range.stop)
        while(port in self._used_ports):
            port = random.randint(
                self._ephemeral_port_range.start, 
                self._ephemeral_port_range.stop)
        
        self._used_ports.add(port)

        return port
   

    def _get_port_from_packet(self, packet, source: bool) -> int:
        """Extracts the port from a TCP, UDP, or ICMP (desination unreachable) packet"""
        invert = False

        if packet.haslayer(TCP):
            layer = packet[TCP]
        elif packet.haslayer(UDP):
            layer = packet[UDP]
        elif packet.haslayer(ICMP):
            if packet[ICMP].type == 3:
                invert = True
                if packet.haslayer(UDPerror):
                    layer = packet[UDPerror]
                elif packet.haslayer(TCPerror):
                    layer = packet[TCPerror]
                    
        else:
            raise Exception("Only UDP and TCP suppoerted")
        
        if (source and not invert) or ((not source) and invert):
            return layer.sport
        else:
            return layer.dport     


class FilteredPacketSniffterThread(Thread):
    """A helper class that asynchronously sniffs packets on a specified interface using Scapy.
    
    This class was implemented so that Scapy can exexute in a thread.
    """
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