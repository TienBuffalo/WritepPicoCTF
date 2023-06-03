from pwn import *

r = ssh(user = "ctf-player",host= "saturn.picoctf.net",port =61167,password = "3f39b042")
r.interactive()
