#!/bin/env python3 
import pyshark
import json
import subprocess
import time

capture = pyshark.LiveCapture(interface='lo', bpf_filter='tcp and port 8443')
timestr = time.strftime("%Y%m%d-%H%M%S")
with open("ja3_capture.data", "w") as fp:
   fp.write("pcap data \n");

while True:
    for packet in capture.sniff_continuously(packet_count=5):
        if hasattr(packet, 'tls'):
            with open("ja3_capture.data", "a") as fp:
                handshake = packet.tls.handshake
                print("handshake: {}".format(handshake))
                fp.write("handshake: {}".format(handshake))
                fp.write("\n")
                print("record_version: {}". format(packet.tls.record_version))
                fp.write("record_version: {}". format(packet.tls.record_version))
                fp.write("\n")
                print("handshake_vesion: {}".format(
                         packet.tls.handshake_version));
                fp.write("handshake_vesion: {}".format(
                         packet.tls.handshake_version));
                fp.write("\n")
                fp.write("handshake_cipher_suites_length: {}".format(
                         packet.tls.handshake_cipher_suites_length))
                fp.write("\n")
                fp.write("handshake_ciphersuites: {}".format(
                         packet.tls.handshake_ciphersuites))
                fp.write("\n")
                fp.write("{}".format(packet.tls))  
                fp.write("\n")
                fp.write("*"*50)
                fp.write("\n")
