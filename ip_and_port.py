###############################################################################
# (c) 2022 Michael MacFadden
#
# CSC-841 Cyber Operations II
# Lab 08 and 09
###############################################################################

from dataclasses import dataclass
from ipaddress import IPv4Address

@dataclass(eq=True, frozen=True)
class IpAndPort:
    """A simple data class that combines an IPv4 address and a port"""

    ip: IPv4Address
    
    port: int