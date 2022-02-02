#! /usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

#p = remote("chall.pwnable.tw", 10000)
p = process("./start")
gdb.attach(p, 'b _start')

p.interactive()
