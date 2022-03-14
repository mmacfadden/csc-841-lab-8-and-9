#!/usr/bin/env python3
 
###############################################################################
# (c) 2022 Michael MacFadden
#
# CSC-841 Cyber Operations II
# Lab 08 and 09
###############################################################################

from nat_engine import NatEngine
import netifaces
import argparse
import signal


##
## Argument processing
##
parser = argparse.ArgumentParser(description='A simple NAT Server.')

parser.add_argument('inside', metavar='inside', type=str,
                    help='The interface name of the inside netwrok interface')
parser.add_argument('outside', metavar='outside', type=str,
                    help='The interface name of the outside netwrok interface')
parser.add_argument('-v','--verbose', action='store_true',
                    help='Print additional information')
args = parser.parse_args()


##
## Argument validation
##

inside_interface = args.inside
outside_interface = args.outside

interfaces = netifaces.interfaces()

if not outside_interface in interfaces:
    print(f"Outside interface '{outside_interface}' does not exists.  Valid interfaces: {interfaces}")
    exit(1)

if not inside_interface in interfaces:
    print(f"Inside interface '{inside_interface}' does not exists.  Valid interfaces: {interfaces}")
    exit(1)


# Handle the CTRL-C signal and gracefully exit.
def interrupt_handler(signum, frame):
    print("\nCTRL-C received, shutting down.")
    exit(0)
 
signal.signal(signal.SIGINT, interrupt_handler)


# Start the Nat Server. This will block.
nat = NatEngine(inside_interface, outside_interface, args.verbose)
nat.start()
