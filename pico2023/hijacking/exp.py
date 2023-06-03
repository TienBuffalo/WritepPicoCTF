#!/usr/bin/python3

from pwn import *

a = ssh(user="picoctf",host="saturn.picoctf.net",port=52846,password="HYGhWsmPyf")
a.interactive()
