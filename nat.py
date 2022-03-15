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
parser.add_argument('-i', '--idle-timeout', metavar='seconds', type=int, default=60,
                    help='The number of seconds after which a connection is assumed to have timed out.')
parser.add_argument('-c', '--idle-check-interval', metavar='seconds', type=int, default=10,
                    help='How often idel connections should be scanned for.')
parser.add_argument('-v','--verbose', action='store_true', required=False,
                    help='Print additional information')
args = parser.parse_args()


##
## Argument validation
##

inside_interface = args.inside
outside_interface = args.outside

interfaces = netifaces.interfaces()

if not outside_interface in interfaces:
    print(f"Error: Outside interface '{outside_interface}' does not exists.  Valid interfaces: {interfaces}")
    exit(1)

if not inside_interface in interfaces:
    print(f"Error: Inside interface '{inside_interface}' does not exists.  Valid interfaces: {interfaces}")
    exit(1)

if inside_interface == outside_interface:
    print(f"Error: Inside interface and outside interface can not be the same.")
    exit(1)


# Handle the CTRL-C signal and gracefully exit.
def interrupt_handler(signum, frame):
    print("\nCTRL-C received, shutting down.")
    exit(0)
 
signal.signal(signal.SIGINT, interrupt_handler)


# Start the Nat Server. This will block.
nat = NatEngine(inside_interface, outside_interface, args.idle_timeout, args.idle_check_interval, args.verbose)
nat.start()
