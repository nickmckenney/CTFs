buf = p.readuntil(">")
easy_addr = int(buf.split(b"WOW:")[1][:-1], 0)
OR

stack= p.recvline().strip().split()[-1]

stack = ''.join([chr(int(stack[i:i+2],16)) for i in range(2, len(stack),2)])
stack = stack.rjust(8,'\x00')
stack = pwn.u64(stack)
p.sendlineafter('> ','2')

