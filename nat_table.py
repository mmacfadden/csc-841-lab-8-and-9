###############################################################################
# (c) 2022 Michael MacFadden
#
# CSC-841 Cyber Operations II
# Lab 08 and 09
###############################################################################

from ip_and_port import IpAndPort
from dataclasses import dataclass
from typing import Optional

@dataclass
class TcpSession:
    inside_fin_seq_no: Optional[int] = None
    inside_fin_acked: bool = False

    outside_fin_seq_no: Optional[int] = None
    outside_fin_acked: bool = False

@dataclass
class NatEntry:
    """Represents a single entry in the NatTabe
    """
    source_inside: IpAndPort
    source_outside: IpAndPort
    dest_outside: IpAndPort

    last_packet_time: float 
    tcp_session_state: Optional[TcpSession] = None


class NatTable:

    def __init__(self) -> None:
        self.inside_map: dict[IpAndPort, NatEntry] = {}
        self.outside_map: dict[IpAndPort, NatEntry] = {}

    def has_entry(self, entry: NatEntry) -> bool:
        return self.get_entry_by_inside_ip_and_port(entry.source_inside)

    def has_inside_ip_and_port(self, ip_and_port: IpAndPort) -> bool:
        return ip_and_port in self.inside_map

    def has_outside_ip_and_port(self, ip_and_port: IpAndPort) -> bool:
        return ip_and_port in self.outside_map

    def add_entry(self, entry: NatEntry) -> None:
        self.inside_map[entry.source_inside] = entry
        self.outside_map[entry.source_outside] = entry

    def get_entry_by_inside_ip_and_port(self, ip_and_port) -> NatEntry:
        return self.inside_map.get(ip_and_port)

    def get_entry_by_outside_ip_and_port(self, ip_and_port) -> NatEntry:
        return self.outside_map.get(ip_and_port)

    def remove_by_inside_ip_and_port(self, ip_and_port: IpAndPort) -> None:
        entry = self.get_entry_by_inside_ip_and_port(ip_and_port)
        self.remove_entry(entry)

    def remove_by_outside_ip_and_port(self, ip_and_port: IpAndPort) -> None:
        entry = self.get_entry_by_outside_ip_and_port(ip_and_port)
        self.remove_entry(entry)

    def remove_entry(self, entry: NatEntry) -> None:
        del self.inside_map[entry.source_inside]
        del self.outside_map[entry.source_outside]

    def remove_timed_out_entries(self) -> None:
        print("checking for timeout")