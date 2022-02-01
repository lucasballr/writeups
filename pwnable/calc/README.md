# Calc

Alrighty then. This was definitely a tough one. Time to put my thinking hat on and get to work. First thing's first, lets pull this up in ghidra and see what this is all about.

```c
void main(){
  signal(0xe,timeout);
  alarm(0x3c);
  puts("=== Welcome to SECPROG calculator ===");
  fflush((FILE *)stdout);
  calc();
  puts("Merry Christmas!");
  return;
```

Looks like it's got a timer on it, so you can't take too long to do your thing on the program. Good thing we'll only end up needing a few seconds. The function we want to look at here is the `calc()` function:

```c
calc (){
  while( true ) {
    bzero(local_410,0x400);
    iVar1 = get_expr(local_410,0x400);
    if (iVar1 == 0) break;
    init_pool(&local_5a4);
    iVar1 = parse_expr(local_410,&local_5a4);
    if (iVar1 != 0) {
      printf("%d\n",auStack1440[local_5a4 + -1]);
      fflush((FILE *)stdout);
    }
  }
  }
```
Within this function it looks like it clears some space for us to work with `bzero()`. Then it will get the user input with `get_expr()`. Then it parses the user input with `parse_expr()` Then it takes the result of the parsed user input and prints it out. My first idea here was maybe there's some inputs that could give some weird results, so I started out by just throwing some random inputs at it to see what happened. None of my attempts really got me anything. I decided to take a hard look at the `get_expr()` and `parse_expr()` functions to see what was going on under the hood:

```c
int get_expr(int param_1,int param_2){
  local10 = 0;
  while (local10 < param2) {
    sVar1 = read(0,&local_11,1);
    if ((sVar1 == -1)  (local_11 == '\n')) break;
    if ((((local_11 == '+')  (((local_11 == '-'  (local_11 == '*'))  (local_11 == '/'))))
        (local_11 == '%'))  (('/' < local_11 && (local_11 < ':')))) {
      *(char *)(local10 + param_1) = local_11;
      local10 = local10 + 1;
    }
  }
  return local10;
}
```

Looks like this function reads exactly 400 characters of user input and puts it on the on in the `local10` buffer. This is only the case if the characters include `+,-,*,/,%,0-9`. These are the characters I had to work with. Now lets take a look at the `parse_expr()` function where all the magic happens.

```
int parse_expr(void *param_1, void *param_2
  bzero(local_74,100);
  local_88 = 0;
  do {
    if (9 < (int)*(char *)((int)param_1 + local_88) - 0x30U) {
      __n = (int)param_1 + (local_88 - (int)local_8c);
      __s1 = (char *)malloc(__n + 1);
      memcpy(__s1,local_8c,__n);
      __s1[__n] = '\0';
      iVar2 = strcmp(__s1,"0");
      if (iVar2 == 0) {
        puts("prevent division by zero");
        fflush((FILE *)stdout);
        uVar3 = 0;
        goto LAB_0804935f;
      }
      iVar2 = atoi(__s1);
      if (0 < iVar2) {
        iVar1 = *param_2;
        *param_2 = iVar1 + 1;
        param_2[iVar1 + 1] = iVar2;
      }
      if ((*(char *)((int)param_1 + local_88) != '\0') &&
         (9 < (int)*(char *)((int)param_1 + local_88 + 1) - 0x30U)) {
        puts("expression error!");
        fflush((FILE *)stdout);
        uVar3 = 0;
        goto LAB_0804935f;
      }
      local_8c = (void *)((int)param_1 + local_88 + 1);
      if (local_74[local_84] == '\0') {
        local_74[local_84] = *(char *)((int)param_1 + local_88);
      }
      else {
        switch(*(undefined *)((int)param_1 + local_88)) {
        case 0x25:
        case 0x2a:
        case 0x2f:
          if ((local_74[local_84] == '+') || (local_74[local_84] == '-')) {
            local_74[local_84 + 1] = *(char *)((int)param_1 + local_88);
            local_84 = local_84 + 1;
          }
          else {
            eval(param_2,(int)local_74[local_84]);
            local_74[local_84] = *(char *)((int)param_1 + local_88);
          }
          break;
        default:
          eval(param_2,(int)local_74[local_84]);
          local_84 = local_84 + -1;
          break;
        case 0x2b:
        case 0x2d:
          eval(param_2,(int)local_74[local_84]);
          local_74[local_84] = *(char *)((int)param_1 + local_88);
        }
      }
      if (*(char *)((int)param_1 + local_88) == '\0') {
        for (; -1 < local_84; local_84 = local_84 + -1) {
          eval(param_2,(int)local_74[local_84]);
        }
        uVar3 = 1;
    local_88 = local_88 + 1;
  } while( true );
```
Looks like the first part is just converting each string of number characters into integers that could be evaluated. Then it would put the numbers on one buffer and the expression symbols on another buffer In This case, it's useful to take a look at how these buffers are being used to be evaluated. Looks like the ghidra decompiler had some issues with this section, but we'll just assume that the eval function takes an integer buffer and a char. The char is the expression symbol while the buffer is an array of numbers that was created in the parsing. Alright lets take a look at the eval function:
```
void eval(int param_1,char param_2)

{
  if (param_2 == '+') {
    param_1[param_1 + -1] = param_1[param_1 + -1] + param_1[param_1];
  }
  else {
    if (param_2 < ',') {
      if (param_2 == '') {
        param_1[param_1 + -1] = param_1[*param_1 + -1] * param_1[param_1];
      }
    }
    else {
      if (param_2 == '-') {
        param_1[param_1 + -1] = param_1[param_1 + -1] - param_1[param_1];
      }
      else {
        if (param_2 == '/') {
          param_1[param_1 + -1] = param_1[param_1 + -1] / param_1[*param_1];
        }
      }
    }
  }
  *param_1 = *param_1 + -1;
  return;
}
```

Alright so I was right. The char gets checked to see how the evaluation should go, then it evaluates with the buffer at index -1 and index 1. Wait what??? This took far too long to notice, but there's a problem with trying to access the -1 index. If the sanitation is working correctly, this might actually be secure, but lets take a look at the sanitation to see if theres a problem here:

```
iVar2 = strcmp(__s1,"0");
if (iVar2 == 0) {
    puts("prevent division by zero");
    fflush((FILE *)stdout);
    uVar3 = 0;
    goto LAB_0804935f;
}
iVar2 = atoi(__s1);
    if (0 < iVar2) {
        iVar1 = *param_2;
        *param_2 = iVar1 + 1;
        param_2[iVar1 + 1] = iVar2;
    }
```
So looking at it here it will check if the number we entered is "0". If it is, we get an expression error and we resturn back to user input. If it's not "0" it will convert the number to an integer and save it to the buffer that will later be used in the eval function, **but only if the converted number is larger than 0**. So what if we entered "00" for the first input. Lets try it:
```
=== Welcome to SECPROG calculator ===
00+10
0
```
Okay we didn't get an expression error, but I don't exactly know what's going on here. I guess I'll take a look back at the eval function to see what's going on. When it runs the eval function we see that it sets the buffer[-1] to the value that was calculated. So with our "00" input, the first number was never allocated, so it must be evaluating our second number with whatever is before the buffer. Lets take a look at the order of variable definitions to see what comes before the buffer:

```c
int iVar1;
char *s1;
int iVar2;
undefined4 uVar3;
size_t n;
int in_GS_OFFSET;
void *local_8c;
int local_88;
int local_84; // Right before the buffer
char local_74 [100]; // The buffer
int local_10;
```

So `local_84` is our culprit. If we look above: `eval(param_2,(int)local_74[local_84]);` its the index of the buffer! And this is the value that ultimately gets output to the screen. I wrote a program to go through an arbitrary number of buffer indexes and I was able to read everything on the stack in the area. If you take a look at `e.py` you can see that it's the `list_stack()` function. So now we have arbitrary read. We can't really do much with that unless we can write things to memory. This is where it gets incredibly complicated. So lets say you plug in `00+20`. You're gonna get a response with the value of `buffer[20]`. But this parser runs on a loop until the expression is finished. So what if you sent `00+20+30`? We start out with the eval function outputting `buffer[20]`, but we've done something here. We altered the index variable to `index = 20` so we run the loop again and we have `buffer[index-1] = buffer[index-1] + 30`. Well there you go, the value at buffer[19] just got set to whatever it was +30. We got arbitrary write.

Now to figure out what we can do with this arbitrary read and write. I figured it would be a safe bet to try to overwrite the return address so I ran my `list_stack()` in gdb to find where that was. I found it at buffer[359]. This means I had to overwrite the buffer at index 360 to overwrite the return address. Lets try it:

```
=== Welcome to SECPROG calculator ===
00+360+20
-5770548

Segmentation fault (core dumped)
```
There we go, we got a seg fault because we overwrote the return address. Since we can alter anything on the stack why not try some ROP? I took a look at the functions I had to work with and found that there were no `execve` or `system`. Uh oh... I guess I'm gonna have to go the hard way and manually call execve with a ROP and `int 0x80`. But wait:

```
pwndbg> search "/bin/sh"
pwndbg>
```
Looks like I'm gonna also have to put "/bin/sh" somewhere so I can use it when I call execve. This stumped me for a while because I could put "/bin/sh" on the stack with my arbitrary write, but I couldn't access it, because (after a lot of trial an error) I was unable to put a value higher than 0x7fffffff on the stack, and the stack just happened to start at 0xffff0000 making this a big problem. I'd have to use `read()` to read the user input and place the "/bin/sh" somewhere in memory. So I did exactly that, I built a ROP chain that would read my input then return back to the `calc()` function so I could continue the exploit. Then I used the `calc()` function to create another ROP chain that would use our string to all `execve("/bin/sh", 0, 0)`. The way I did it took hours of trial and error because building the stack from the return address to the `int 0x80` was incredibly hard. Turns out doing that, each value that you changed would alter the next value. Which makes sense because of the way the `eval` function is put together. This means that each address that I entered had to be an offset of the previous address. After hours of trial and error, I got it. I connected up to the server and got the flag. `FLAG{C:\Windows\System32\calc.exe}`

Later I realized that if I built the stack backwards I wouldn't have had to go through all that trouble, but I guess some things you just gotta learn the hard way.
