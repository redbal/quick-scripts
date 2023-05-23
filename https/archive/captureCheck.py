#!/bin/env python3 
import pyshark
import json
import subprocess
import time

capture = pyshark.LiveCapture(interface='lo0', bpf_filter='tcp and port 8443')
timestr = time.strftime("%Y%m%d-%H%M%S")

#for packet in capture.sniff_continuously(packet_count=5):
for packet in capture.sniff_continuously():
    if hasattr(packet, 'tls'):
        if hasattr(packet.tls, 'handshake_ja3'):
            print("JA3: {}".format(packet.tls.handshake_ja3))
            print("JA3 FULL: {}".format(packet.tls.handshake_ja3_full))