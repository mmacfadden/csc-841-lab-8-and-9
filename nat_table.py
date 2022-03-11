###############################################################################
# (c) 2022 Michael MacFadden
#
# CSC-841 Cyber Operations II
# Lab 08 and 09
###############################################################################

from ip_and_port import IpAndPort
from dataclasses import dataclass

@dataclass(eq=True, frozen=True)
class NatEntry:
    """Represents a single entry in the NatTabe
    """
    source_inside: IpAndPort
    source_outside: IpAndPort
    dest_outside: IpAndPort

class NatTable:
    
    inside_map: dict[IpAndPort, NatEntry] = {}
    outside_map: dict[IpAndPort, NatEntry] = {}

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
        self._remove_entry(entry)

    def remove_by_outside_ip_and_port(self, ip_and_port: IpAndPort) -> None:
        entry = self.get_entry_by_outside_ip_and_port(ip_and_port)
        self._remove_entry(entry)

    def _remove_entry(self, entry: NatEntry) -> None:
        del self.inside_map[entry.source_inside]
        del self.outside_map[entry.source_outside]