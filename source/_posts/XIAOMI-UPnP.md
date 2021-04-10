---
title: 小米路由器_MiniUPnP协议
date: 2019-04-21 14:51:45
tags:
- 小米
- 路由器
- MiniUPnP
categories: IOT
description: 非常经典的UPnP，Classic~
---

# 概述
[HomePage](http://miniupnp.free.fr/)
[OpenWRT与miniUPnP](https://openwrt.org/docs/guide-user/firewall/upnp/miniupnpd)
>MiniUPnP项目提供了支持UPnP IGD(互联网网关设备)规范的软件。
在MiniUPnPd中添加了NAT-PMP和PCP支持。 对于客户端（MiniUPnPc）使用libnatpmp来支持NAT-PMP。
MiniUPnP守护程序（MiniUPnPd）支持OpenBSD，FreeBSD，NetBSD，DragonFly BSD（Open）Solaris和Mac OS X以及pf或ipfw（ipfirewall）或ipf和Linux with netfilter。 MiniUPnP客户端（MiniUPnPc）和MiniSSDPd是便携式的，可以在任何POSIX系统上运行。 MiniUPnPc也适用于MS Windows和AmigaOS（版本3和4）。

https://2014.ruxcon.org.au/assets/2014/slides/rux-soap_upnp_ruxcon2014.pptx
https://www.akamai.com/us/en/multimedia/documents/white-paper/upnproxy-blackhat-proxies-via-nat-injections-white-paper.pdf
https://www.defcon.org/images/defcon-19/dc-19-presentations/Garcia/DEFCON-19-Garcia-UPnP-Mapping.pdf

## UPnP IGD客户端轻量级库和UPnP IGD守护进程
大多数家庭adsl /有线路由器和Microsoft Windows 2K/XP都支持UPnP协议。 MiniUPnP项目的目标是提供一个免费的软件解决方案来支持协议的“Internet网关设备”部分。
>用于UPnP设备的Linux SDK（libupnp）对我来说似乎太沉重了。 我想要最简单的库，占用空间最小，并且不依赖于其他库，例如XML解析器或HTTP实现。 所有代码都是纯ANSI C.

miniupnp客户端库在x86 PC上编译，代码大小不到50KB。
miniUPnP守护程序比任何其他IGD守护程序小得多，因此非常适合在低内存设备上使用。 它也只使用一个进程而没有其他线程，不使用任何system（）或exec（）调用，因此保持系统资源使用率非常低。
该项目分为两个主要部分：
- MiniUPnPc，客户端库，使应用程序能够访问网络上存在的UPnP“Internet网关设备”提供的服务。 在UPnP术语中，MiniUPnPc是UPnP控制点。
- MiniUPnPd，一个守护进程，通过作为网关的linux或BSD（甚至Solaris）为您的网络提供这些服务。 遵循UPnP术语，MiniUPnPd是UPnP设备。
开发MiniSSDPd与MiniUPnPc，MiniUPnPd和其他协作软件一起工作：1. MiniSSDPd监听网络上的SSDP流量，因此MiniUPnPc或其他UPnP控制点不需要执行发现过程，并且可以更快地设置重定向；   2.  MiniSSDPd还能够代表MiniUPnPd或其他UPnP服务器软件回复M-SEARCH SSDP请求。 这对于在同一台机器上托管多个UPnP服务很有用。
守护进程现在也可以使用netfilter用于linux 2.4.x和2.6.x. 可以使它在运行OpenWRT的路由器设备上运行。
由于某些原因，直接使用MiniUPnP项目中的代码可能不是一个好的解决方案。
由于代码很小且易于理解，因此为您自己的UPnP实现提供灵感是一个很好的基础。 C ++中的[KTorrent](http://ktorrent.org/) UPnP插件就是一个很好的例子。

## MiniUPnP客户端库的实用性
只要应用程序需要侦听传入的连接，MiniUPnP客户端库的使用就很有用。例如：P2P应用程序，活动模式的FTP客户端，IRC（用于DCC）或IM应用程序，网络游戏，任何服务器软件。
- 路由器的UPnP IGD功能的典型用法是使用MSN Messenger的文件传输。 MSN Messenger软件使用Windows XP的UPnP API打开传入连接的端口。 为了模仿MS软件，最好也使用UPnP。
- 已经为XChat做了一个补丁，以展示应用程序如何使用miniupnp客户端库。
- 传输，一个免费的软件BitTorrent客户端正在使用miniupnpc和libnatpmp。

## MiniUPnP守护进程的实用性
UPnP和NAT-PMP用于改善NAT路由器后面的设备的互联网连接。 诸如游戏，IM等的任何对等网络应用可受益于支持UPnP和/或NAT-PMP的NAT路由器。最新一代的Microsoft XBOX 360和Sony Playstation 3游戏机使用UPnP命令来启用XBOX Live服务和Playstation Network的在线游戏。 据报道，MiniUPnPd正在与两个控制台正常工作。 它可能需要一个精细的配置调整。

## 安全
UPnP实施可能会受到安全漏洞的影响。 错误执行或配置的UPnP IGD易受攻击。 安全研究员HD Moore做了很好的工作来揭示现有实施中的漏洞：[通用即插即用（PDF）中的安全漏洞](http://hdm.io/writing/originals/SecurityFlawsUPnP.pdf)。 一个常见的问题是让SSDP或HTTP/SOAP端口对互联网开放：它们应该只能从LAN访问。


# 协议栈
工作流程
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555830377/paper/111.png)

Linux体系结构
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555830425/paper/112.png)

## 发现
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555830465/paper/113.png)
给定一个IP地址（通过DHCP获得），UPnP网络中的第一步是发现。
当一个设备被加入到网络中并想知道网络上可用的UPnP服务时，UPnP检测协议允许该设备向控制点广播自己的服务。通过UDP协议向端口1900上的多播地址239.255.255.250发送发现消息。此消息包含标头，类似于HTTP请求。此协议有时称为HTTPU（HTTP over UDP）：
```
M-SEARCH * HTTP / 1.1
主机：239.255.255.250 ：1900
MAN：ssdp：discover
MX：10
ST：ssdp：all
```
所有其他UPnP设备或程序都需要通过使用UDP单播将类似的消息发送回设备来响应此消息，并宣布设备或程序实现哪些UPnP配置文件。对于每个配置文件，它实现一条消息发送：
```
HTTP / 1.1 200 OK
CACHE-CONTROL：max-age = 1800
EXT：
LOCATION：http：//10.0.0.138：80 / IGD.xml
SERVER：SpeedTouch 510 4.0.0.9.0 UPnP / 1.0（DG233B00011961）
ST：urn：schemas-upnp-org：service：WANPPPConnection：1
USN：uuid：UPnP-SpeedTouch510 :: urn：schemas-upnp-org：service：WANPPPConnection：1
```
类似地，当一个控制点加入到网络中的时候，它也能够搜索到网络中存在的、感兴趣的设备相关信息。这两种类型的基础交互是一种仅包含少量、重要相关设备信息或者它的某个服务。比如，类型、标识和指向更详细信息的链接。
UPnP检测协议是 ***基于简单服务发现协议（SSDP）*** 的。

## 描述
UPnP网络的下一步是描述。当一个控制点检测到一个设备时，它对该设备仍然知之甚少。为了使控制点了解更多关于该设备的信息或者和设备进行交互，控制点必须从设备发出的检测信息中包含的URL获取更多的信息。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555830499/paper/114.png)
某个设备的UPnP描述是 **XML** 的方式,通过http协议，包括品牌、厂商相关信息，如型号名和编号、序列号、厂商名、品牌相关URL等。描述还包括一个嵌入式设备和服务列表，以及控制、事件传递和存在相关的URL。对于每种设备，描述还包括一个命令或动作列表，包括响应何种服务，针对各种动作的参数；这些变量描述出运行时设备的状态信息，并通过它们的数据类型、范围和事件来进行描述。

## 控制
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555830533/paper/1133.png)
UPnP网络的下一步是控制。当一个控制点获取到设备描述信息之后，它就可以向该设备发送指令了。为了实现此，控制点发送一个合适的控制消息至服务相关控制URL（包含在设备描述中）。
```
<service>
  <serviceType> urn：schemas-upnp-org：service：WANPPPConnection：1 </ serviceType>
  <serviceId> urn：upnp-org： serviceId：wanpppc：pppoa </ serviceId>
  <controlURL> / upnp / control / wanpppcpppoa </ controlURL>
  <eventSubURL> / upnp / event / wanpppcpppoa </ eventSubURL>
  <SCPDURL> /WANPPPConnection.xml </ SCPDURL>
</ service>
```
要发送SOAP请求，只需要controlURL标记内的URL。控制消息也是通过 ***简单对象访问协议（SOAP）*** 用XML来描述的。类似函数调用，服务通过返回动作相关的值来回应控制消息。动作的效果，如果有的话，会反应在用于刻画运行中服务的相关变量。

## 事件通知
下一步是事件通知。UPnP中的事件 ***协议基于GENA*** 。一个UPnP描述包括一组命令列表和刻画运行时状态信息的变量。服务在这些变量改变的时候进行更新，控制点可以进行订阅以获取相关改变。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555830573/paper/115.png)
服务通过发送事件消息来发布更新。事件消息包括一个或多个状态信息变量以及它们的当前数值。这些消息也是采用XML的格式，用通用事件通知体系进行格式化。一个特殊的初始化消息会在控制点第一次订阅的时候发送，它包括服务相关的变量名及值。为了支持多个控制点并存的情形，事件通知被设计成对于所有的控制点都平行通知。因此，所有的订阅者同等地收到所有事件通知。
当状态变量更改时，新状态将发送到已订阅该事件的所有程序/设备。程序/设备可以通过eventSubURL来订阅服务的状态变量，该URL可以在LOCATION指向的URL中找到。
```
<service>
  <serviceType> urn：schemas-upnp-org：service：WANPPPConnection：1 </ serviceType>
  <serviceId> urn：upnp-org：serviceId：wanpppc：pppoa </ serviceId>
  <controlURL> / upnp / control / wanpppcpppoa </ controlURL>
  <eventSubURL> / upnp / event / wanpppcpppoa <
  <SCPDURL> /WANPPPConnection.xml </ SCPDURL>
</ service>
```

## 展示
最后一步是展示。如果设备带有存在URL，那么控制点可以通过它来获取设备存在信息，即在浏览器中加载URL，并允许用户来进行相关控制或查看操作。具体支持哪些操作则是由存在页面和设备完成的。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555830618/paper/1111.png)

## NAT穿透
UPnP为NAT（网络地址转换）穿透带来了一个解决方案：**互联网网关设备协议（IGD）**。NAT穿透允许UPnP数据包在没有用户交互的情况下，无障碍的通过路由器或者防火墙（假如那个路由器或者防火墙支持NAT）。


# SOAP和UPnP
|协议|全称|
|-----|-----|
|UPnP|Universal Plug and Play|
|SSDP|Simple Service Discovery Protocol|
|SCPD|Service Control Protocol Definition|
|SOAP|Simple Object Access Protocol|

## UPnP - Discovery
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555576753/paper/1.png)
## UPnP – Description
- XML文件通常托管在高位的TCP端口
- 版本信息
upnp.org spec
通常为1.0
- 设备定义
型号名和编号、序列号、厂商名、品牌相关URL
服务列表：服务类型；SCPD URL；Control URL；Event URL
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555576810/paper/2.png)
## UPnP – SCPD
- 定义服务动作和参数的XML文件
- 版本信息
和描述一致
- 动作列表
动作名
参数：参数名、方向（输入输出）、变量名
- 变量列表
变量名、数据类型
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555577220/paper/3.png)
## UPnP – Control
- 这里用到了SOAP
- 主要是RPC服务或CGI脚本的前端
- SOAP封装
• XML格式的API调用
• 描述XML中的服务类型
• 来自SCPD XML的动作名称和参数
- POST封装到control URL
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555577719/paper/4.png)
## TL;DR
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555577820/paper/5.png)
## 好的一面
- Control AV equipment
- Home automation
- Network administration
- Physical security systems (ok, easy there buddy)
- Industrial monitoring and control (uh…what?)
- And this is just the official specs
All our devices can talk to each other! Brave new worlds of remote control and automation! Have your toaster turn on the lights, set the TV to the news channel, and send you a text message when breakfast is ready! The future is now! Nothing could possibly go wrong!
## 关于安全
1. 嵌入式设备
- 有限的内存和处理能力
- 硬件和软件开发人员通常是完全不同的公司
- 复制和粘贴开发
- 保持低成本
- 不完全关心/懂行
2. 部署
- 数以百万计的面向互联网的UPnP设备
- 要计算的供应商太多
- 前端是标准化的，后端甚至在同一供应商内也有所不同
- 难以修补/更新固件
- 仅仅因为你可以，并不意味着你应该
3. XML解析很难
- 需要大量系统资源
- 自由格式的用户提供的数据
- 2013年，2.5％的CVE与XML相关[2]，其中，近36％的患者CVSS严重程度为7或以上
- 随着XML的用例增长，版本也越来越多：递归错误，XXE，命令注入等......

# 攻击面
- UPnP服务
• HTTP头解析
• SSDP解析
• OS命令注入
• 信息披露
- SOAP服务
• HTTP头解析
• XML解析
• 注射用品
• OS命令
• SQL注入
• SOAP注入
• 信息披露
• 可疑级别的未经身份验证的设备控制
## Attack surface – UPnP
- [CVE-2012-5958](https://community.rapid7.com/docs/DOC-2150)
去年由HD Moore（众多之一）披露；调用strncpy将ST头中的字符串复制到TempBuf[COMMAND_LEN]；strncpy的长度参数基于冒号之间的字符数
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555580242/paper/6.png)

- D-Link DIR-815 [UPnP命令注入](http://shadow-file.blogspot.com/2013/02/dlink-dir-815-upnp-command-injection.html)
去年由Zach Cutlip披露;ST头的内容作为参数传递给M-SEARCH.sh;无需验证
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555580904/paper/7.png)

## Attack surface – SOAP
- XBMC soap_action_name[缓冲区溢出](http://www.exploit-db.com/exploits/15347/)
由n00b于2010年10月公布;ProcessHttpPostRequest函数分配静态大小的缓冲区;调用sscanf将SOAPAction标头的值复制到其中，没有边界检查
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555581152/paper/8.png)

- 博通SetConnectionType[格式字符串漏洞](http://sebug.net/paper/Exploits-Archives/2013-exploits/1301-exploits/DC-2013-01-003.txt)
去年Leon Juranic和Vedran Kajic透露；SetConnectionType操作将NewConnectionType参数的值提供给snprintf；不对用户控制的值进行检查
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555581385/paper/9.png)

- [CVE-2014-3242](http://www.pnigos.com/?p=260)
今年早些时候由pnig0s披露;SOAPpy允许在SOAP请求中声明用户定义的XML外部实体;不对用户控制的值进行检查
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555581672/paper/10.png)

- [CVE-2014-2928](http://seclists.org/fulldisclosure/2014/May/32)
Brandon Perry今年早些时候公布了（PBerry Crunch！）;F5 iControl API set_hostname操作将hostname参数的值传递给shell;再一次，不对用户控制的值进行消毒
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555581840/paper/11.png)

- [CVE-2011-4499，CVE-2011-4500，CVE-2011-4501，CVE-2011-4503，CVE-2011-4504，CVE-2011-4505，CVE-2011-4506，更多？](http://toor.do/DEFCON-19-Garcia-UPnP-Mapping-WP.pdf)
Daniel Garcia在Defcon 19上披露; UPnP IGD 使用AddPortMapping和DeletePortMapping等操作来允许远程管理路由规则;缺乏身份验证，可在WAN接口上使用; 使攻击者能够执行：•NAT遍历 •外部/内部主机端口映射 •内部LAN的外部网络扫描

## 如何测试
- 了解您的网络
M-SEARCH你连接的每个网络以监听新的NOTIFY消息
- 如果您不需要UPnP，请将其禁用
如果不在设备上，则在路由器上
- 随时掌握固件更新
并非总是自动的
- 模糊测试
Burp – http://portswigger.net/burp/
WSFuzzer – https://www.owasp.org/index.php/Category:OWASP_WSFuzzer_Project
Miranda – http://code.google.com/p/miranda-upnp/

# 对小米WIFI路由器的UPnP分析
## 使用工具扫描
### 使用Metasploit检查

```
msfconsole
msf5 > use auxiliary/scanner/upnp/ssdp_msearch
msf5 auxiliary(scanner/upnp/ssdp_msearch) > set RHOSTS 192.168.31.0/24
RHOSTS => 192.168.31.0/24
msf5 auxiliary(scanner/upnp/ssdp_msearch) > run

[*] Sending UPnP SSDP probes to 192.168.31.0->192.168.31.255 (256 hosts)
[*] 192.168.31.1:1900 SSDP MiWiFi/x UPnP/1.1 MiniUPnPd/2.0 | http://192.168.31.1:5351/rootDesc.xml | uuid:f3539dd5-8dc5-420c-9070-c6f66d27fc8c::upnp:rootdevice
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```
从中可以得到这些信息：
- UPnP/1.1
- MiniUPnPd/2.0

### 使用nmap进行扫描

```
nmap -p1900，5351 192.168.31.1

PORT     STATE    SERVICE
1900/tcp filtered upnp
5351/tcp open     nat-pmp
```
***nat-pmp***
NAT端口映射协议（英语：NAT Port Mapping Protocol，缩写NAT-PMP）是一个能自动创建网络地址转换（NAT）设置和端口映射配置而无需用户介入的网络协议。该协议能自动测定NAT网关的外部IPv4地址，并为应用程序提供与对等端交流通信的方法。NAT-PMP于2005年由苹果公司推出，为更常见的ISO标准互联网网关设备协议（被许多NAT路由器实现）的一个替代品。该协议由互联网工程任务组（IETF）在RFC 6886中发布。
NAT-PMP使用用户数据报协议（UDP），在5351端口运行。该协议没有内置的身份验证机制，因为转发一个端口通常不允许任何活动，也不能用STUN方法实现。NAT-PMP相比STUN的好处是它不需要STUN服务器，并且NAT-PMP映射有一个已知的过期时间，应用可以避免低效地发送保活数据包。
NAT-PMP是端口控制协议（PCP）的前身。
https://laucyun.com/25118b151a3386b7beff250835fe7e98.html
2014年10月，Rapid7安全研究员Jon Hart公布，因厂商对NAT-PMP协议设计不当，估计公网上有1200万台网络设备受到NAT-PMP漏洞的影响。NAT-PMP协议的规范中特别指明，NAT网关不能接受来自外网的地址映射请求，但一些厂商的设计并未遵守此规定。黑客可能对这些设备进行恶意的端口映射，进行流量反弹、代理等攻击。

### netstat扫描

```
Proto Recv-Q Send-Q Local Address         Foreign Address    State    in out PID/Program name
tcp   0      0      :::5351               :::*               LISTEN   0 0 18068/miniupnpd
udp   0      0      192.168.31.1:5351     0.0.0.0:*          0        0 18068/miniupnpd
udp   0      0      0.0.0.0:1900          0.0.0.0:*          1414113  1827652 18068/miniupnpd
```
端口1900在UPnP发现的过程中使用，5351通常为端口映射协议NAT-PMP运行的端口

### [miranda](https://www.ethicalhacker.net/columns/heffner/plug-n-play-network-hacking/)

```
sudo python2 miranda.py -i wlx44334c388fbd -v

Miranda v1.3
The interactive UPnP client
Craig Heffner, http://www.devttys0.com


Binding to interface wlx44334c388fbd ...

Verbose mode enabled!
upnp> msearch

Entering discovery mode for 'upnp:rootdevice', Ctl+C to stop...

****************************************************************
SSDP reply message from 192.168.31.1:5351
XML file is located at http://192.168.31.1:5351/rootDesc.xml
Device is running MiWiFi/x UPnP/1.1 MiniUPnPd/2.0
****************************************************************

upnp> host get 0

Requesting device and service info for 192.168.31.1:5351 (this could take a few seconds)...

Device urn:schemas-upnp-org:device:WANDevice:1 does not have a presentationURL
Device urn:schemas-upnp-org:device:WANConnectionDevice:1 does not have a presentationURL
Host data enumeration complete!

upnp> host list

	[0] 192.168.31.1:5351

upnp> host info 0

xmlFile : http://192.168.31.1:5351/rootDesc.xml
name : 192.168.31.1:5351
proto : http://
serverType : MiWiFi/x UPnP/1.1 MiniUPnPd/2.0
upnpServer : MiWiFi/x UPnP/1.1 MiniUPnPd/2.0
dataComplete : True
deviceList : {}

upnp> host info 0 deviceList

InternetGatewayDevice : {}
WANDevice : {}
WANConnectionDevice : {}

upnp> host info 0 deviceList WANConnectionDevice

  manufacturerURL : http://miniupnp.free.fr/
  modelName : MiniUPnPd
  UPC : 000000000000
  modelNumber : 20180830
  friendlyName : WANConnectionDevice
  fullName : urn:schemas-upnp-org:device:WANConnectionDevice:1
  modelDescription : MiniUPnP daemon
  UDN : uuid:f3539dd5-8dc5-420c-9070-c6f66d27fc8e
  modelURL : http://miniupnp.free.fr/
  manufacturer : MiniUPnP
  services : {}

upnp> host info 0 deviceList WANConnectionDevice services WANIPConnection

    eventSubURL : /evt/IPConn
    controlURL : /ctl/IPConn
    serviceId : urn:upnp-org:serviceId:WANIPConn1
    SCPDURL : /WANIPCn.xml
    fullName : urn:schemas-upnp-org:service:WANIPConnection:1
    actions : {}
    serviceStateVariables : {}

upnp> host info 0 deviceList WANConnectionDevice services WANIPConnection actions

      AddPortMapping : {}
      GetNATRSIPStatus : {}
      GetGenericPortMappingEntry : {}
      GetSpecificPortMappingEntry : {}
      ForceTermination : {}
      GetExternalIPAddress : {}
      GetConnectionTypeInfo : {}
      GetStatusInfo : {}
      SetConnectionType : {}
      DeletePortMapping : {}
      RequestConnection : {}

upnp> host info 0 deviceList WANConnectionDevice services WANIPConnection serviceStateVariables

        InternalClient : {}
        Uptime : {}
        PortMappingLeaseDuration : {}
        PortMappingDescription : {}
        RemoteHost : {}
        PossibleConnectionTypes : {}
        ExternalPort : {}
        RSIPAvailable : {}
        ConnectionStatus : {}
        PortMappingNumberOfEntries : {}
        ExternalIPAddress : {}
        ConnectionType : {}
        NATEnabled : {}
        LastConnectionError : {}
        InternalPort : {}
        PortMappingProtocol : {}
        PortMappingEnabled : {}

upnp> host summary 0

          Host: 192.168.31.1:5351
          XML File: http://192.168.31.1:5351/rootDesc.xml
          InternetGatewayDevice
          	manufacturerURL: http://www.mi.com
          	modelName: MiWiFi Router
          	UPC: 000000000000
          	modelNumber: 20180830
          	presentationURL: http://miwifi.com/
          	friendlyName: MiWiFi router
          	fullName: urn:schemas-upnp-org:device:InternetGatewayDevice:1
          	modelDescription: MiWiFi Router
          	UDN: uuid:f3539dd5-8dc5-420c-9070-c6f66d27fc8c
          	modelURL: http://www1.miwifi.com
          	manufacturer: Xiaomi
          WANDevice
          	manufacturerURL: http://miniupnp.free.fr/
          	modelName: WAN Device
          	UPC: 000000000000
          	modelNumber: 20180830
          	friendlyName: WANDevice
          	fullName: urn:schemas-upnp-org:device:WANDevice:1
          	modelDescription: WAN Device
          	UDN: uuid:f3539dd5-8dc5-420c-9070-c6f66d27fc8d
          	modelURL: http://miniupnp.free.fr/
          	manufacturer: MiniUPnP
          WANConnectionDevice
          	manufacturerURL: http://miniupnp.free.fr/
          	modelName: MiniUPnPd
          	UPC: 000000000000
          	modelNumber: 20180830
          	friendlyName: WANConnectionDevice
          	fullName: urn:schemas-upnp-org:device:WANConnectionDevice:1
          	modelDescription: MiniUPnP daemon
          	UDN: uuid:f3539dd5-8dc5-420c-9070-c6f66d27fc8e
          	modelURL: http://miniupnp.free.fr/
          	manufacturer: MiniUPnP
```

- 使用miranda发送UPnP命令
**获取外部IP地址**

```
upnp> host send 0 WANConnectionDevice WANIPConnection GetExternalIPAddress

NewExternalIPAddress : 172.16.173.231
```
**增加一个端口映射，将路由器上端口为1900的服务映射到外网端口8080**

```
upnp> host send 0 WANConnectionDevice WANIPConnection AddPortMapping

Required argument:
	Argument Name:  NewPortMappingDescription
	Data Type:      string
	Allowed Values: []
	Set NewPortMappingDescription value to: HACK

Required argument:
	Argument Name:  NewLeaseDuration
	Data Type:      ui4
	Allowed Values: []
	Value Min:      0
	Value Max:      604800
	Set NewLeaseDuration value to: 0

Required argument:
	Argument Name:  NewInternalClient
	Data Type:      string
	Allowed Values: []
	Set NewInternalClient value to: 192.168.31.1

Required argument:
	Argument Name:  NewEnabled
	Data Type:      boolean
	Allowed Values: []
	Set NewEnabled value to: 1

Required argument:
	Argument Name:  NewExternalPort
	Data Type:      ui2
	Allowed Values: []
	Set NewExternalPort value to: 8080

Required argument:
	Argument Name:  NewRemoteHost
	Data Type:      string
	Allowed Values: []
	Set NewRemoteHost value to:

Required argument:
	Argument Name:  NewProtocol
	Data Type:      string
	Allowed Values: ['TCP', 'UDP']
	Set NewProtocol value to: TCP

Required argument:
	Argument Name:  NewInternalPort
	Data Type:      ui2
	Allowed Values: []
	Value Min:      1
	Value Max:      65535
	Set NewInternalPort value to: 1900
```


```
upnp> host send 0 WANConnectionDevice WANIPConnection GetSpecificPortMappingEntry

  Required argument:
  	Argument Name:  NewExternalPort
  	Data Type:      ui2
  	Allowed Values: []
  	Set NewExternalPort value to: 8080

  Required argument:
  	Argument Name:  NewRemoteHost
  	Data Type:      string
  	Allowed Values: []
  	Set NewRemoteHost value to:

  Required argument:
  	Argument Name:  NewProtocol
  	Data Type:      string
  	Allowed Values: ['TCP', 'UDP']
  	Set NewProtocol value to: TCP

  NewPortMappingDescription : HACK
  NewLeaseDuration : 0
  NewInternalClient : 192.168.31.1
  NewEnabled : 1
  NewInternalPort : 1900
```

**可以无需验证地删除映射**
```
upnp> host send 0 WANConnectionDevice WANIPConnection DeletePortMapping
```
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555918880/paper/2231.png)
虽然UPnP是一种很少理解的协议，但它在绝大多数家庭网络上都很活跃，甚至在某些公司网络上也是如此。许多设备支持UPnP以便于消费者使用，但是，它们通常支持不允许任何服务自动执行的操作，尤其是未经授权的情况下。更糟糕的是，协议实现本身很少以安全思维构建，使其可以进一步利用。
防止本地/远程利用UPnP的最佳方法是在任何/所有网络设备上禁用该功能。然而，考虑到这个协议和其他“自动魔术”协议旨在帮助懒惰的用户，他们可能不知道这些协议的危险，唯一真正的解决方案是让供应商更加关注他们的设计和实施，并且更加安全。

## 浏览配置文件
### 通过find命令搜索
<pre>root@XiaoQiang:/# find -name *upnp*
./etc/rc.d/S95miniupnpd
./etc/init.d/miniupnpd
./etc/hotplug.d/iface/50-miniupnpd
./etc/config/upnpd
./tmp/upnp.leases
./tmp/etc/miniupnpd.conf
./tmp/run/miniupnpd.pid
./usr/lib/lua/luci/view/web/setting/upnp.htm
./usr/sbin/miniupnpd
./usr/share/miniupnpd
./www/xiaoqiang/web/css/upnp.css
./data/etc/rc.d/S95miniupnpd
./data/etc/init.d/miniupnpd
./data/etc/hotplug.d/iface/50-miniupnpd
./data/etc/config/upnpd</pre>

- /etc/rc.d 启动的配置文件和脚本


```
!/bin/sh /etc/rc.common
# Copyright (C) 2006-2011 OpenWrt.org

START=95
SERVICE_USE_PID=1
upnpd_get_port_range() {
        local _var="$1"; shift
        local _val
        config_get _val "$@"
        case "$_val" in
                [0-9]*[:-][0-9]*)
                        export -n -- "${_var}_start=${_val%%[:-]*}"
                        export -n -- "${_var}_end=${_val##*[:-]}"
                ;;
                [0-9]*)
                        export -n -- "${_var}_start=$_val"
                        export -n -- "${_var}_end="
                ;;
        esac
}
conf_rule_add() {
        local cfg="$1"
        local tmpconf="$2"
        local action external_port_start external_port_end int_addr
        local internal_port_start internal_port_end

        config_get action "$cfg" action "deny"               # allow or deny
        upnpd_get_port_range "ext" "$cfg" ext_ports "0-65535" # external ports: x, x-y, x:y
        config_get int_addr "$cfg" int_addr "0.0.0.0/0"       # ip or network and subnet mask (internal)
        upnpd_get_port_range "int" "$cfg" int_ports "0-65535" # internal ports: x, x-y, x:y or range

        # Make a single IP IP/32 so that miniupnpd.conf can use it.
        case "$int_addr" in
                */*) ;;
                *) int_addr="$int_addr/32" ;;
        esac

        echo "${action} ${ext_start}${ext_end:+-}${ext_end} ${int_addr} ${int_start}${int_end:+-}${int_end}" >>$tmpconf
}
upnpd_write_bool() {                                                                                                   
        local opt="$1"                                                                                                 
        local def="${2:-0}"                                                                                            
        local alt="$3"                                                                                                 
        local val                                                                                                      

        config_get_bool val config "$opt" "$def"                                                                       
        if [ "$val" -eq 0 ]; then                                                                                      
                echo "${alt:-$opt}=no" >> $tmpconf                                                                     
        else                                                                                                           
                echo "${alt:-$opt}=yes" >> $tmpconf                                                                    
        fi                                                                                                             
}                                                                                                                      

boot() {                                                                                                               
        return 0                                                                                                       
}                                                                                                                      

start() {                                                                                                              
        config_load "upnpd"                                                                                            
        local extiface intiface upload download logging secure enabled natpmp                                          
        local extip port usesysuptime conffile serial_number model_number                                              
        local uuid notify_interval presentation_url enable_upnp                                                        
        local upnp_lease_file clean_ruleset_threshold clean_ruleset_interval                                           

        config_get extiface config external_iface                                                                      
        config_get intiface config internal_iface                                                                      
        config_get extip config external_ip                                                                            
        config_get port config port 5000                                                                               
        config_get upload   config upload                                                                              
        config_get download config download                                                                            
        config_get_bool logging config log_output 0                                                                    
        config_get conffile config config_file                                                                         
        config_get serial_number config serial_number                                                                  
        config_get model_number config model_number                                                                    
        config_get uuid config uuid                                                                                    
        config_get notify_interval config notify_interval                                                              
        config_get presentation_url config presentation_url                                                            
        config_get upnp_lease_file config upnp_lease_file                                                              
        config_get clean_ruleset_threshold config clean_ruleset_threshold                                              
        config_get clean_ruleset_interval config clean_ruleset_interval                                                

        local args                                                                                                     

        . /lib/functions/network.sh        
        local ifname                                                                                                   
        network_get_device ifname ${extiface:-wan}                                                                     

        if [ -n "$conffile" ]; then                                                                                    
                args="-f $conffile"                                                                                    
        else                                                                                                           
                local tmpconf="/var/etc/miniupnpd.conf"                                                                
                args="-f $tmpconf"                                                                                     
                mkdir -p /var/etc                                                                                      

                echo "ext_ifname=$ifname" >$tmpconf                                                                    

                [ -n "$extip" ] && \                                                                                   
                        echo "ext_ip=$extip" >>$tmpconf                                                                

                local iface                                                                                            
                for iface in ${intiface:-lan}; do                                                                      
                        local device                                                                                   
                        network_get_device device "$iface" && {                                                        
                                echo "listening_ip=$device" >>$tmpconf                                                 
                        }                                                                                              
                done                                                                                                   

                [ "$port" != "auto" ] && \                                                                             
                        echo "port=$port" >>$tmpconf                                                                   

                config_load "upnpd"                                                                                    
                upnpd_write_bool enable_natpmp 1                             
                upnpd_write_bool enable_upnp 1                               
                upnpd_write_bool secure_mode 1                               
                upnpd_write_bool system_uptime 1    
                [ -n "$upnp_lease_file" ] && {                                                                         
                        touch $upnp_lease_file                                                                         
                        echo "lease_file=$upnp_lease_file" >>$tmpconf                                                  
                }                                                                                                      

                [ -n "$upload" -a -n "$download" ] && {                                                                
                        echo "bitrate_down=$(($download * 1024 * 8))" >>$tmpconf                                       
                        echo "bitrate_up=$(($upload * 1024 * 8))" >>$tmpconf                                           
                }                                                                                                      

                [ -n "${presentation_url}" ] && \                                                                      
                        echo "presentation_url=${presentation_url}" >>$tmpconf                                         

                [ -n "${notify_interval}" ] && \                                                                       
                        echo "notify_interval=${notify_interval}" >>$tmpconf                                           

                [ -n "${clean_ruleset_threshold}" ] && \                                                               
                        echo "clean_ruleset_threshold=${clean_ruleset_threshold}" >>$tmpconf                           

                [ -n "${clean_ruleset_interval}" ] && \                                                                
                        echo "clean_ruleset_interval=${clean_ruleset_interval}" >>$tmpconf                             

                [ -z "$uuid" ] && {                                                                                    
                        uuid="$(cat /proc/sys/kernel/random/uuid)"                                                     
                        uci set upnpd.config.uuid=$uuid                                                                
                        uci commit upnpd                                                                               
                }                                                                                                      

                [ "$uuid" = "nocli" ] || \                                                                             
                        echo "uuid=$uuid" >>$tmpconf                                                                   

                [ -n "${serial_number}" ] && \                                                                         
                        echo "serial=${serial_number}" >>$tmpconf                                                      

                [ -n "${model_number}" ] && \                                               
                        echo "model_number=${model_number}" >>$tmpconf        
                        config_foreach conf_rule_add perm_rule "$tmpconf"                                                          
                    fi                                                                                                             


                    if [ -n "$ifname" ]; then                                                                                      
                            # start firewall                                                                                       
                            iptables -L MINIUPNPD >/dev/null 2>/dev/null || fw3 reload                                             

                            if [ "$logging" = "1" ]; then                                                                          
                                    SERVICE_DAEMONIZE=1 \                                                                          
                                    service_start /usr/sbin/miniupnpd $args -d                                                     
                            else                                                                                                   
                                    SERVICE_DAEMONIZE= \                                                                           
                                    service_start /usr/sbin/miniupnpd $args                                                        
                            fi                                                                                                     
                    else                                                                                                           
                            logger -t "upnp daemon" "external interface not found, not starting"                                   
                    fi                                                                                                             
                    return 0                                                                                                       
            }                                                                                                                      

            stop() {                                                                                                               
                    service_stop /usr/sbin/miniupnpd                                                                               

                    iptables -t nat -F MINIUPNPD 2>/dev/null                                            
                    iptables -t filter -F MINIUPNPD 2>/dev/null                                         
                    return 0                                                                            
            }                                              

```


















SmartController
messagingagent
