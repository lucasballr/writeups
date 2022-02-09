# Making shellcode

This is a nice setup that allows you to make some custom shellcode.

### Usage:

Write your assembly code under main in `shellcode.S` Then you can compile it into shellcode with these commands.

`make 32` Will make shellcode for 32-bit architectures.
`make 64` Will make shellcode for 64-bit architectures.
`make objdump` will list out an objdump of your shellcode.
`make print` can be called after compiling to get a stringified version of your shellcode.
`make dump` will print out the opcodes of your compiled shellcode.

This should be everything to get started using this tool to make shellcode.
