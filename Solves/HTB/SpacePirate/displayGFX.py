#!/usr/bin/python3
import pwn
# run straight
e = pwn.context.binary = pwn.ELF("./space")

# p = e.process()

# Must be ran from tmux
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py\nbreak *main\nc")

# must have ssh/nc creds
# p = pwn.ssh()
# p = pwn.connect()

p.interactive()
