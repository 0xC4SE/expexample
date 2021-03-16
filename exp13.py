from pwn import *
context.arch = "amd64"
io = process("./")
io.recvline()
io.sendline()
