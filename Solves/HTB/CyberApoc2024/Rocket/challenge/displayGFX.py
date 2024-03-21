#!/usr/bin/python3
from pwn import *
import struct
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
elf = context.binary = ELF("./pwn", checksec=False)
libc = ELF('./glibc/libc.so.6')
p = elf.debug()
p.interactive()