#!/usr/bin/env python3
 
###############################################################################
# (c) Michael MacFadden
#
# CSC-841 Cyber Operations II
# Lab 09 and 09
#
# 
# Developed With:
#   Python: 3.9.1
#   Scapy:  2.4.4
#
###############################################################################

from nat_engine import NatEngine
import os
import netifaces

inside_interface = "eth2"
outside_interface = "eth1"


interfaces = netifaces.interfaces()

if not outside_interface in interfaces:
    raise Exception("bad outside interface")

if not inside_interface in interfaces:
    raise Exception("bad inside interface")


nat = NatEngine(inside_interface, outside_interface, False)
nat.start()