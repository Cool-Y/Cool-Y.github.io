---
title: 远程调试小米路由器固件
date: 2019-07-25 22:17:08
tags:
- 路由器
- 小米
- 调试
categories:
- IOT
---

# 0x00 背景与简介
--------------
在分析嵌入式设备的固件时，只采用静态分析方式通常是不够的，你需要实际执行你的分析目标来观察它的行为。在嵌入式Linux设备的世界里，很容易把一个调试器放在目标硬件上进行调试。如果你能在自己的系统上运行二进制文件，而不是拖着硬件做分析, 将会方便很多，这就需要用QEMU进行仿真。
虽然QEMU在模拟核心芯片组包括CPU上都做的很不错，但是QEMU往往不能提供你想运行的二进制程序需要的硬件。最常见问题是在运行系统服务，如Web服务器或UPnP守护进程时，缺乏NVRAM。解决方法是使用nvram-faker库拦截由libnvram.so提供的nvram_get()调用。即使解决了NVRAM问题，该程序还可能会假设某些硬件是存在的，如果硬件不存在，该程序可能无法运行，或者即便它运行了，行为可能也与在其目标硬件上运行时有所不同。针对这种情况下，我认为有三种解决方法：
1. 修补二进制文件。这取决于期望什么硬件，以及它不存在时的行为是什么。
2. 把复杂的依赖于硬件的系统服务拆分成小的二级制文件。如跳过运行Web服务器，仅仅从shell脚本运行cgi二进制文件。因为大多数cgi二进制文件将来自Web服务器的输入作为标准输入和环境变量的组合，并通过标准输出将响应发送到Web服务器。
3. 拿到设备的shell，直接在真机上进行调试，这是最接近真实状况的方法。



# REF
------------
**综合：**
[国外大神的博客](https://shadow-file.blogspot.com/2015/01/dynamically-analyzing-wifi-routers-upnp.html)
[通过QEMU和IDAPro远程调试设备固件](https://wooyun.js.org/drops/%E9%80%9A%E8%BF%87QEMU%20%E5%92%8C%20IDA%20Pro%E8%BF%9C%E7%A8%8B%E8%B0%83%E8%AF%95%E8%AE%BE%E5%A4%87%E5%9B%BA%E4%BB%B6.html)
[MIPS漏洞调试环境安装及栈溢出](https://ray-cp.github.io/archivers/MIPS_Debug_Environment_and_Stack_Overflow)
[环境搭建onCTFWIKI](https://wiki.x10sec.org/pwn/arm/environment/)
[路由器漏洞训练平台](https://www.anquanke.com/post/id/171918)
[路由器0day漏洞挖掘实战](https://www.anquanke.com/post/id/180714)
[逆向常用工具](https://5alt.me/wiki/%E9%80%86%E5%90%91)


**环境搭建：**
[路由器漏洞挖掘测试环境的搭建之问题总结](https://xz.aliyun.com/t/3826)


**Linux相关知识**
[qcow2、raw、vmdk等镜像格式](http://xstarcd.github.io/wiki/Cloud/qcow2_raw_vmdk.html)
[Linux 引导过程内幕](http://joe.is-programmer.com/posts/17753.html)
[Linux启动过程](https://zhuanlan.zhihu.com/p/32051645)

**调试案例**
[CVE-2019-10999复现](https://xz.aliyun.com/t/5681)
[《家用路由器0day漏洞挖掘》部分案例](https://ray-cp.github.io/archivers/router_vuln_book_note)
[TP-LINK WR941N路由器研究](https://paper.seebug.org/448/)



# 0x01 基础条件
----------
- 一系列的工具，包括：
**binwalk** 帮助你解包固件
**buildroot** mips交叉编译环境帮助你在x86平台下编译mips架构的目标程序 https://xz.aliyun.com/t/2505#toc-6
**qemu** 帮助你模拟mips环境
**MIPS gdbinit** 文件使得使用gdb调试mips程序时更方便 https://github.com/zcutlip/gdbinit-mips
**miranda工具** 用于UPnP分析 https://code.google.com/p/miranda-upnp/
**MIPS静态汇编审计** 辅助脚本 https://github.com/giantbranch/mipsAudit
**静态编译的gdbserver**  https://github.com/rapid7/embedded-tools/tree/master/binaries/gdbserver

- 一个**mips Linux**环境：
在qemu系统模式下，需要模拟整个计算机系统




# 0x02 qemu-用户模式
----------
在user mode下使用qemu执行程序有两种情况，一是目标程序为**静态链接**，那么可以直接使用qemu。另一种是目标程序依赖于**动态链接**库，这时候就需要我们来**指明库的位置**，否则目标程序回到系统`/lib`文件下寻找共享库文件。
在 *《揭秘家用路由器0day》* 这本书里面，他给出的方法是：
```shell
$ cp $(which qemu-mipsel) ./
$ sudo chroot . ./qemu-mipsel ./usr/sbin/miniupnpd
```
他把qemu-mipsel复制到固件文件目录下，然后`chroot`命令改变qemu执行的根目录到当前目录，按理说此时应该可以找到依赖库,但是结果却是`chroot: failed to run command ‘./qemu-mipsel’: No such file or directory`


在网上找到了[解决方法](https://xz.aliyun.com/t/3826)：需要安装使用 **qemu-mips-static** 才可以
```shell
$ apt-get install qemu binfmt-support qemu-user-static
$ cp $(which qemu-mipsel-static ) ./
$ sudo chroot . ./qemu-mipsel-static ./usr/sbin/miniupnpd
```
这里还可利用`-E`用来设置环境变量，`LD_PRELOAD "./lib"`用来劫持系统调用，另外还有`-g`开启调试模式


除此之外，也在[CTF-WIKI](https://wiki.x10sec.org/pwn/arm/environment/)上找到了另一种方法：使用 **qemu-mips 的 -L 参数**指定路由器的根目录
```shell
$ qemu-mipsel -L . ./usr/sbin/miniupnpd
```

## 模拟miniupnp
由于没有指定参数，所以这里miniupnpd只把usage和notes打印给我们了：
```shell
Usage:
	./usr/sbin/miniupnpd [-f config_file] [-i ext_ifname] [-o ext_ip]
		[-a listening_ip] [-p port] [-d] [-U] [-S] [-N]
		[-u uuid] [-s serial] [-m model_number]
		[-t notify_interval] [-P pid_filename]
		[-B down up] [-w url] [-r clean_ruleset_interval]
		[-A "permission rule"] [-b BOOTID]

Notes:
	There can be one or several listening_ips.
	Notify interval is in seconds. Default is 30 seconds.
	Default pid file is '/var/run/miniupnpd.pid'.
	Default config file is '/etc/miniupnpd.conf'.
	With -d miniupnpd will run as a standard program.
	-S sets "secure" mode : clients can only add mappings to their own ip
	-U causes miniupnpd to report system uptime instead of daemon uptime.
	-N enables NAT-PMP functionality.
	-B sets bitrates reported by daemon in bits per second.
	-w sets the presentation url. Default is http address on port 80
	-A use following syntax for permission rules :
	  (allow|deny) (external port range) ip/mask (internal port range)
	examples :
	  "allow 1024-65535 192.168.1.0/24 1024-65535"
	  "deny 0-65535 0.0.0.0/0 0-65535"
	-b sets the value of BOOTID.UPNP.ORG SSDP header
	-h prints this help and quits.
```

根据miniupnpd的启动文件`/etc/init.d/miniupnpd`，小米使用了启动脚本来配置`service_start /usr/sbin/miniupnpd -f conffile -d`
其配置文件connfile如下所示：
```
ext_ifname=eth0.2
listening_ip=br-lan
port=5351
enable_natpmp=yes
enable_upnp=yes
secure_mode=no
system_uptime=yes
lease_file=/tmp/upnp.leases
bitrate_down=8388608
bitrate_up=4194304
uuid=e1f3a0ec-d9d4-4317-a14b-130cdd18d092
allow 1024-65535 0.0.0.0/0 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
```
- [ ] 可见因路由器的特殊性，具有两张网卡(eth0.2&br-lan)，暂时我还没想出应该怎么解决，是否采用qemu虚拟机配置网络可以解决呢？反正我采用下面这种粗暴的方式是不可以的(直接指定配置文件)
```shell
$ sudo qemu-mipsel -L . ./usr/sbin/miniupnpd -f ../../MiniUPnP/miniupnpd.conf -d
miniupnpd[7687]: system uptime is 5652 seconds
miniupnpd[7687]: iptc_init() failed : iptables who? (do you need to insmod?)
miniupnpd[7687]: Failed to init redirection engine. EXITING
```



# 0x03 qemu-系统模式
-----------
系统模式命令格式：`$qemu system-mips [option][disk_image]`

## MIPS系统网络配置
下载mips系统内核和虚拟机镜像 https://people.debian.org/~aurel32/qemu/
```
To use this image, you need to install QEMU 1.1.0 (or later). Start QEMU
with the following arguments for a 32-bit machine:
  - qemu-system-mipsel -M malta -kernel vmlinux-2.6.32-5-4kc-malta -hda debian_squeeze_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0"
  - qemu-system-mipsel -M malta -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_wheezy_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0"
```

**1. 安装依赖文件**`apt-get install uml-utilities bridge-utils`

**2. 修改主机网络配置**
```
auto lo
iface lo inet loopback

auto ens33
iface eth0 inet dhcp

#auto br0
iface br0 inet dhcp
  bridge_ports ens33
  bridge_maxwait 0
```

**3. 修改qemu网络接口启动脚本**
```
$ sudo vim /etc/qemu-ifup  
$ sudo chmod a+x /etc/qemu-ifup
#!/bin/sh
echo "Executing /etc/qemu-ifup"
echo "Bringing $1 for bridged mode..."
sudo /sbin/ifconfig $1 0.0.0.0 promisc up
echo "Adding $1 to br0..."
sudo /sbin/brctl addif br0 $1
sleep 3
```
```
$ sudo /etc/init.d/networking restart
```

**4. qemu启动配置**
```
$ sudo ifdown ens33
$ sudo ifup br0
```

**5. 启动mips虚拟机**
`sudo qemu-system-mipsel -M malta -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_wheezy_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0"  -net nic,macaddr=00:16:3e:00:00:01 -net tap -nographic`

我自闭了，ubuntu18根本没法联网，于是我用了ubuntu14.0



# 0x04 在mips虚拟机中调试
------------
现在通过上面的配置我得到了这样一台虚拟机，并通过ssh连接上去。
```shell
root@debian-mipsel:/home/user/mi_wifi_r3_112# ifconfig
eth1      Link encap:Ethernet  HWaddr 00:16:3e:00:00:01
          inet addr:192.168.31.246  Bcast:192.168.31.255  Mask:255.255.255.0
          inet6 addr: fe80::216:3eff:fe00:1/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:89377 errors:75 dropped:360 overruns:0 frame:0
          TX packets:9114 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:103978997 (99.1 MiB)  TX bytes:924287 (902.6 KiB)
          Interrupt:10 Base address:0x1020

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:8 errors:0 dropped:0 overruns:0 frame:0
          TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:560 (560.0 B)  TX bytes:560 (560.0 B)
```
已经把我的小米固件全部上传到这个虚拟机中
```shell
root@debian-mipsel:/home/user/mi_wifi_r3_112# ls
bin  data  dev  etc  extdisks  lib  libnvram-faker.so  mnt  opt  overlay  proc  qemu-mipsel-static  readonly  rom  root  sbin  sys  tmp  userdisk  usr  var  www
```
和用户模式一样，还是使用chroot，因为目标二进制是和固件的库链接的，很可能不能跟Debian的共享库一起工作。
```shell
root@debian-mipsel:/home/user/mi_wifi_r3_112# chroot . ./usr/sbin/miniupnpd
Usage:
        ./usr/sbin/miniupnpd [-f config_file] [-i ext_ifname] [-o ext_ip]
                [-a listening_ip] [-p port] [-d] [-U] [-S] [-N]
                [-u uuid] [-s serial] [-m model_number]
                [-t notify_interval] [-P pid_filename]
                [-B down up] [-w url] [-r clean_ruleset_interval]
                [-A "permission rule"] [-b BOOTID]

Notes:
        There can be one or several listening_ips.
        Notify interval is in seconds. Default is 30 seconds.
        Default pid file is '/var/run/miniupnpd.pid'.
        Default config file is '/etc/miniupnpd.conf'.
        With -d miniupnpd will run as a standard program.
        -S sets "secure" mode : clients can only add mappings to their own ip
        -U causes miniupnpd to report system uptime instead of daemon uptime.
        -N enables NAT-PMP functionality.
        -B sets bitrates reported by daemon in bits per second.
        -w sets the presentation url. Default is http address on port 80
        -A use following syntax for permission rules :
          (allow|deny) (external port range) ip/mask (internal port range)
        examples :
          "allow 1024-65535 192.168.1.0/24 1024-65535"
          "deny 0-65535 0.0.0.0/0 0-65535"
        -b sets the value of BOOTID.UPNP.ORG SSDP header
        -h prints this help and quits.
```
直接运行起来，还是只打印出usage，这里我注意到之前忽视的地方`Default config file is '/etc/miniupnpd.conf'.`，所以我不再使用`-f`参数来指定，而是把配置文件放在默认目录下，在小米路由器里，`ext_ifname`是外部ip，`listening_ip`是内部ip。但是我这里还没有开启两个，所以都赋值为一张网卡。
```shell
ext_ifname=eth1
listening_ip=eth1
port=5351
enable_natpmp=yes
enable_upnp=yes
secure_mode=no
system_uptime=yes
lease_file=/tmp/upnp.leases
bitrate_down=8388608
bitrate_up=4194304
uuid=e1f3a0ec-d9d4-4317-a14b-130cdd18d092
allow 1024-65535 0.0.0.0/0 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
```
在这个配置下，运行miniupnp还是被告知`daemon(): No such file or directory`
```
root@debian-mipsel:/home/user/mi_wifi_r3_112# chroot . ./usr/sbin/miniupnpd
root@debian-mipsel:/home/user/mi_wifi_r3_112# daemon(): No such file or directory
```
我起初猜测是因为缺乏`NVRAM`
> 在运行系统服务，如Web服务器或UPnP守护进程时，缺乏NVRAM。非易失性RAM通常是包含配置参数的设备快速存储器的一个分区。当一个守护进程启动时，它通常会尝试查询NVRAM，获取其运行时配置信息。有时一个守护进程会查询NVRAM的几十甚至上百个参数。

于是我运行二进制程序时，使用LD_PRELOAD对nvram-faker库进行预加载。它会拦截通常由libnvram.so提供的`nvram_get()`调用。nvram-faker会查询你提供的一个INI风格的配置文件，而不是试图查询NVRAM。
这里有一个链接：https://github.com/zcutlip/nvram-faker
```shell
root@debian-mipsel:/home/user/mi_wifi_r3_112# chroot . /bin/sh -c "LD_PRELOAD=/libnvram-faker.so /usr/sbin/miniupnpd"
root@debian-mipsel:/home/user/mi_wifi_r3_112# daemon(): No such file or directory
```
问题依然存在，daemon是在miniupnpd中常出现的词，猜测，会不会某些函数没有实现？这部分会比较麻烦，需要反汇编。
但是，我们不是可以拿到路由器的shell吗！干嘛还要用qemu模拟再调试，直接上真机！





# 0x05 设备上调试程序
---------------
> 1、有shell权限
> 2、有静态编译的gdbserver或者gdb
>
只要满足上面两个条件，我们就可以通过在路由器上运行`gdbserver_mipsle --attach 0.0.0.0:port PID` 以及 在你的电脑上使用 **gdb-multiarch** 进行调试(先指定架构，然后使用remote功能)轻松地调试设备上地mips程序。
```
pwndbg> set architecture mips (但大多数情况下这一步可以省略, 似乎 pwndbg 能自动识别架构)
pwndbg> target remote localhost:1234
```

能根据固件中的bin得知这是一个小端mips指令集的设备，gdbserver也不用自己编译，直接下载编译好的: https://github.com/rapid7/embedded-tools/tree/master/binaries/gdbserver
把gdbserver.mipsbe通过tftp上传到路由器的/tmp目录下，然后找到目标程序PID：
```
root@XiaoQiang:/# ps |grep miniupnp
12517 root      1772 S    grep miniupnp
28284 root      1496 S    /usr/sbin/miniupnpd -f /var/etc/miniupnpd.conf
```
**gdbserver attach**这个进程，就可以通过**gdb**或者**IDA**远程调试这个程序
