#include <sys/syscall.h>

.global main
.type   main, @function

main:
  ret
  #mov $5, %eax
  #push $5
  #pop %eax
  #push $0x67616c66
  #xor %ecx, %ecx
  #cltd
  #push %esp
  #pop %ebx
  #int $0x80
  
