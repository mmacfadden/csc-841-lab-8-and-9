#!/usr/bin/env python3
 
###############################################################################
# (c) 2022 Michael MacFadden
#
# CSC-841 Cyber Operations II
# Lab 08 and 09
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