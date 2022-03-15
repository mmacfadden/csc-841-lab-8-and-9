###############################################################################
# (c) 2022 Michael MacFadden
#
# CSC-841 Cyber Operations II
# Lab 08 and 09
###############################################################################

class TcpFlags:
    """A static class that stores the TCP Flag Values for Scapy"""

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80