#!/usr/bin/python3

import os

os.system('clear')

f = open('./msg.enc','r')

plain_text = ''

secret = f.read()
print(f"cipher: {secret}")
cipher = bytes.fromhex(secret)
print("")
print(f"after change to bytes {cipher}")

for i in cipher:
    for brute in range(33,126):
        if((123*brute+18)%256) == i:
            plain_text += chr(brute)
            break
print("after decode")
print(plain_text)

