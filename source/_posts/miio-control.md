---
title: 利用miio控制局域网内的小米智能设备
date: 2018-12-15 14:38:15
tags:
- 小米
- miio
- 中间人
- 重放攻击
categories:
- IOT
---
# 控制局域网内的IOT设备
## 中间人攻击—流量分析
### 使用Nmap分析局域网内设备，得到智能设备的IP
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1553323434/miio/1.png)
	小米智能插座：192.168.31.197 网关：192.168.31.147（控制它的手机ip）
### ettercap嗅探智能设备和网关之间的流量
sudo ettercap -i ens33 -T -q -M ARP:remote /192.168.31.197// /192.168.31.147//
### wireshark抓包分析
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1553323435/miio/2.png)
从图中可以看出，设备的命令控制包为UDP传输，既然是UDP协议传输，那么是否可以通过命令包重放攻击来对设备进行控制？
了解到在homeassistant中可实现对小米设备的集成，并在其中对设备进行管理和操作。Homeassistant，主要以Python语言开发，既然它能操控小米设备，那它底层肯定有相关的函数调用库。
为了可以消除对专有软件(米家app)的依赖，并能控制自己的设备，所以出现了MiIo。设备和米家app在同一局域网下使用的加密专有网络协议我们称之为MiIo协议。
Miio库支持的设备有：
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1553323434/miio/3.png)

## 小米IOT控制流程
在同一局域网中，小米设备可以使用专有的加密UDP网络协议进行通信控制。在网络可达的前提下，向小米设备发送hello bytes就可以获得含有token的结构体数据。之后，构造相应的结构体，并且以同样的方式发送给设备即可完成控制。具体流程如下：
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1553323435/miio/4.png)
## 设备Token的获取方式
小米设备的token获取有三种途径：miio获取、从米家app获取、从数据库获取
### miio获取
在ubuntu下，先安装miio，然后发现设备：
npminstall -g miio
miiodiscover
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1553323440/miio/5.png)
但是很可惜，很多设备隐藏了token，使用该方法可能无法获取到token或获取到的token不正确。
### 米家app获取
这种方法需要的mijia app版本较老，且只对部分设备有效。
### 从数据库获取token
这种方法仅在Mi Home 5.0.19之前的版本可用。
该方法是读取手机中米家的app中的数据记录来获取设备的token，具体步骤如下：
-	准备一部获取root权限的安卓手机
-	安装米家app并登录账号
-	进入/data/data/com.xiaomi.smarthome/databases/
-	拷贝db，下载到电脑
-	[前往网站](http://miio2.yinhh.com/)，上传db，点击提交，即可获得token。
-	8894c73cbd5c7224fb4b8a39e360c255
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1553323440/miio/6.png)

## 脚本控制IOT设备
首先随意发送hellobytes获得时间和设备ID，token我们自己设置；然后构造发送的数据结构msg，cmd中的method包括：set_power(控制开关)、get_prop(获取状态)，控制的params是[‘on’]/ [‘off’]，获取状态的params是[‘power’, ‘temperature’]
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1553323440/miio/7.png)
如果获得了token，就能对小米的设备进行操作，如图下面是返回的信息。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1553323440/miio/8.png)
## 总结
从目前的智能家居市场来看，用户不会只使用单个智能设备厂商的设备，所以对于厂商来说，通过开放接口给用户一些局域网的控制“自由”，实现不同厂商设备的联动是一个不错的选择。
从另外一个角度，本文中体现的安全问题我们也不容忽视。如果在局域网中不经过认证就能获取物联网设备的访问凭证，并进而进行控制，无形中给入侵者留了一扇门。例如，攻击者可经过扫描互联网发现家庭路由器，并利用弱口令或设备漏洞获得路由器的shell权限，接下来就可按照文中步骤就可以获得设备token进而控制。好在小米已经在最新的miio版本中修复了这一漏洞，大大提高了攻击者获取token的难度。
