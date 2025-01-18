#!/usr/bin/python3
from pwn import * 

context.binary = exe = ELF('./wide',checksec=False)
#p = remote('94.237.62.166',45582)
start_addr = 0x1118
end_addr = 0x1154

flag = b""
for i in range(start_addr,end_addr,4):
    flag += exe.read(i,1)
print("before decode: ",flag)
print(flag.decode("ascii"))
#p.sendline(flag.decode("ascii"))
