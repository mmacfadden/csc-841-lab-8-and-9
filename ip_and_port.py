from dataclasses import dataclass
from ipaddress import IPv4Address


@dataclass(eq=True, frozen=True)
class IpAndPort:
    ip: IPv4Address
    port: int