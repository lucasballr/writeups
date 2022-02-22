from pwn import *
context.log_level = 'debug'
p = process('./dubblesort',env={"LD_PRELOAD":"./libc_32.so.6"})

gdb.attach(p)
p.interactive()
