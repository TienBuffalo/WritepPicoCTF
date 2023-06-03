#!/usr/bin/python3

from pwn import *

exe = ELF("./vuln",checksec=False)

r = process(exe.path)

r.sendlineafter(b'What number would you like to guess?\n',b'2002')

while 1:
	a = r.recv().decode()
	if 'Nope!\n' not in a:
		break

	r.sendline(b'2002')






r.interactive()