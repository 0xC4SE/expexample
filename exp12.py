from pwn import *
context.arch = "amd64"
#context.log_level = "debug"
io = process("./level1-magicnumber")
for i in range(16):
        b = io.recvuntil("(")
        a = io.recvuntil(")")
        a = a[:-1]
        a = int(a,16)
        if a<=0x18:
            a = 33
        else:
            b = a%16
            if b <= 8:
                a = a-b + 17
            else:
                a = a-b + 33

        io.sendline(str(a))
io.recv()
io.interactive()

            
        


