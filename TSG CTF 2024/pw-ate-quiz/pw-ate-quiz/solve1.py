from pwn import *


def solve():
    io = process('./chall')

    io.recvuntil(b'Enter the password > ')
    io.sendline((chr(0x11) * 31).encode())

    password1 = b''
    for i in range(4, 8):
        io.recvuntil(b'Enter a hint number (0~2) > ')
        io.sendline(str(i).encode())
        password1 += io.recvline()[:-1]

    password2 = b''
    for i in range(8, 12):
        io.recvuntil(b'Enter a hint number (0~2) > ')
        io.sendline(str(i).encode())
        password2 += io.recvline()[:-1]

    password = b''
    for (b1, b2) in zip(password1, password2):
        c = b1 ^ b2 ^ 0x11
        if chr(c).isprintable():
            password += c.to_bytes()

    io.sendline(b'a')
    io.recvuntil(b'Enter the password > ')
    io.sendline(password)

    io.recvline()
    flag = io.recvline().decode()

    io.close()

    return flag


if __name__ == '__main__':
    print(solve())

