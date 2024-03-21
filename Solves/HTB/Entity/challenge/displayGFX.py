#!/usr/bin/python3
import pwn
e = pwn.context.binary = pwn.ELF("./entity")

# p = e.process()
#p = pwn.connect("94.237.58.211","47532")

p = e.debug(gdbscript="source /home/nick/global/halfdisp.py\nbreak *main\nc")

p.interactive()
