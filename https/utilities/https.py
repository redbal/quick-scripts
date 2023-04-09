#!/usr/bin/env python3 
import pyshark
import json
import subprocess
import time
import threading
import ssl, base64
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

hostname = "localhost"
server_address = (hostname, 8443)
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
context.load_cert_chain('mycert.pem')

capture = pyshark.LiveCapture(interface='lo0', bpf_filter='tcp and port 8443')
timestr = time.strftime("%Y%m%d-%H%M%S")

def do_pcap():
    for packet in capture.sniff_continuously():
        if hasattr(packet, 'tls'):
            if hasattr(packet.tls, 'handshake_ja3'):
                print("JA3: {}".format(packet.tls.handshake_ja3))
                print("JA3 FULL: {}".format(packet.tls.handshake_ja3_full))

from Crypto.Cipher import AES
key = b'Sixteen byte key'
#import pdb; pdb.set_trace()A
a = hostname[::-1].encode('utf_8')
b = hostname[::-1][:-5].encode('utf_8')
c = hostname[::-1][:3].encode('utf_8')
d = hostname.encode('utf_8')
e = hostname[:-4].encode('utf_8')
nonce = base64.b64encode(a+b+c+d+e).hex().encode('utf_8')
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
data = b"The answer is no"
ciphertext, tag = cipher.encrypt_and_digest(data)
print("KEY: {}\nNONCE: {}\nTAG: {}\nPLAINTEXT: {}\nCIPHERTEXT: {}\n".format(key, nonce, tag, data, ciphertext))
print("TAG ENCODED: {}\n".format(base64.b64encode(tag)))
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path.endswith("status"):
            self.send_response(HTTPStatus.NO_CONTENT)
        else:   
            self.send_response(200)
        self.end_headers()
        self.wfile.write(base64.b64encode(ciphertext))

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        response = BytesIO()
        response.write(b'This is POST request. ')
        response.write(b'Received: ')
        response.write(body)
        self.wfile.write(response.getvalue())
        self.close()

pcap = threading.Thread(target=do_pcap, args=())
pcap.start()
httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
httpd.socket = context.wrap_socket(httpd.socket,
                               server_side=True)
httpd.serve_forever()
pcap.join()
