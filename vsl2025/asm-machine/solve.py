#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./code')
p = process()


input()

p.interactive()
