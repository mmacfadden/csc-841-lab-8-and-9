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

nat = NatEngine("172.16.103.0/24", "172.16.103.129")

nat.start()