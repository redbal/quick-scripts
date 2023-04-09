#!/usr/bin/env python3
import requests, base64
from Crypto.Cipher import AES

res = requests.get("https://localhost:8443", verify=False)
hostname = "localhost"
print(res.status_code)
print(res.text)
a = hostname[::-1].encode('utf_8')
b = hostname[::-1][:-5].encode('utf_8')
c = hostname[::-1][:3].encode('utf_8')
d = hostname.encode('utf_8')
e = hostname[:-4].encode('utf_8')
print("{} {} {} {} {}".format(a, b, c, d,e))
print(a+b+c+d+e)
print(base64.b64encode(a+b+c+d+e))
print(base64.b64encode(a+b+c+d+e).hex())
nonce = base64.b64encode(a+b+c+d+e).hex().encode('utf-8')
key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext = base64.b64decode(res.text)
with open("ciphertext.enc", "wb") as f:
    f.write(ciphertext)

plaintext = cipher.decrypt(ciphertext)
print("KEY: {}".format(key))
print("NONCE: {}  len: {} type: {}".format(nonce, len(nonce), type(nonce)))
print("CIPHERTEXT DECODED: {}".format(ciphertext))
print("CIPHERTEXT ENCODED: {}".format(res.text))
print("PLAINTEXT: {}".format(plaintext))

