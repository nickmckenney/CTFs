#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
e = context.binary = ELF("./feedme")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
+"\nbreak *0x8049058"
+"\nc"
)
p.sendlineafter("!",b"N")
p.interactive()