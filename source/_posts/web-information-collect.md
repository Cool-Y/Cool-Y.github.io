---
title: 【web】信息收集
date: 2019-11-12 21:04:37
tags:
- web
- ctf
categories:
- web
---

信息收集+常规owasp top 10+逻辑漏洞
https://www.freebuf.com/sectool/94777.html

> 测试范围：*.i.mi.com     *.cloud.mi.com
>

# 0x01 信息收集
https://wh0ale.github.io/2019/02/22/SRC%E4%B9%8B%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86/
http://www.polaris-lab.com/index.php/archives/69/
## 域名信息收集
### whois反查
当你知道目标的域名，你首先要做的就是通过Whoist数据库查询域名的注册信息，Whois数据库是提供域名的注册人信息，包括联系方式，管理员名字，管理员邮箱等等，其中也包括DNS服务器的信息。
默认情况下，Kali已经安装了Whois。你只需要输入要查询的域名即可：`whois mi.com`
```shell
root@kali:~# whois mi.com
Domain Name: MI.COM
Registry Domain ID: 2502844_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.networksolutions.com
Registrar URL: http://networksolutions.com
Updated Date: 2017-12-20T07:20:54Z
Creation Date: 1998-11-06T05:00:00Z
Registrar Registration Expiration Date: 2023-11-05T04:00:00Z
Registrar: NETWORK SOLUTIONS, LLC.
Registrar IANA ID: 2
Reseller:
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registry Registrant ID:
Registrant Name: XIAOMI INC
Registrant Organization: XIAOMI INC
Registrant Street: The Rainbow City Office Building
Registrant City: Beijing
Registrant State/Province: Beijing
Registrant Postal Code: 100085
Registrant Country: CN
Registrant Phone: +86.13911275905
Registrant Phone Ext:
Registrant Fax: +86.1060606666
Registrant Fax Ext:
Registrant Email: dns-admin@xiaomi.com
Registry Admin ID:
Admin Name: Ma, Hongjie
Admin Organization: XIAOMI INC
Admin Street: The Rainbow City Office Building
Admin City: Beijing
Admin State/Province: Beijing
Admin Postal Code: 100085
Admin Country: CN
Admin Phone: +86.13911275905
Admin Phone Ext:
Admin Fax: +86.1060606666
Admin Fax Ext:
Admin Email: dns-admin@xiaomi.com
Registry Tech ID:
Tech Name: Ma, Hongjie
Tech Organization: XIAOMI INC
Tech Street: The Rainbow City Office Building
Tech City: Beijing
Tech State/Province: Beijing
Tech Postal Code: 100085
Tech Country: CN
Tech Phone: +86.13911275905
Tech Phone Ext:
Tech Fax: +86.1060606666
Tech Fax Ext:
Tech Email: dns-admin@xiaomi.com
Name Server: NS3.DNSV5.COM
Name Server: NS4.DNSV5.COM
DNSSEC: unsigned
Registrar Abuse Contact Email: abuse@web.com
Registrar Abuse Contact Phone: +1.8003337680
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
```
除了使用whois命令，也有一些网站提供在线whois信息查询：
whois.chinaz.com/
然后可以看到注册人信息，邮箱等等这样我们可以进行邮箱反查域名，爆破邮箱，社工，域名劫持等等

### DNS服务器查询
![](https://image.3001.net/images/20150202/14228625211610.jpg)

**1. host**
在kali下我们还可以通过host命令来查询dns服务器
```
root@kali:~# host www.mi.com
www.mi.com is an alias for www.mi.com.wscdns.com.
www.mi.com.wscdns.com has address 116.211.251.22
www.mi.com.wscdns.com has address 221.235.187.82
www.mi.com.wscdns.com has IPv6 address 240e:95e:1001::18
```

```
DNS查询：
host -t a domainName
host -t mx domainName

优点：非常直观，通过查询DNS服务器的A记录、CNAME等，可以准确得到相关信息，较全。
缺点：有很大的局限性，很多DNS是禁止查询的。
```

**2. dig**
除了host命令，你也可以使用dig命令对DNS服务器进行挖掘。相对于host命令，dig命令更具有灵活和清晰的显示信息。
```
root@kali:~# dig mi.com any

; <<>> DiG 9.11.5-P4-3-Debian <<>> mi.com any
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8930
;; flags: qr rd ra; QUERY: 1, ANSWER: 7, AUTHORITY: 2, ADDITIONAL: 22

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: b8b49b6c9f27b6bb4704b2375d3bf751d8231fd911f3b57e (good)
;; QUESTION SECTION:
;mi.com.				IN	ANY

;; ANSWER SECTION:
mi.com.			600	IN	SOA	ns3.dnsv5.com. enterprise3dnsadmin.dnspod.com. 1564128772 3600 180 1209600 180
mi.com.			600	IN	TXT	"g5482dbvg8n9bo3vedav36m63q"
mi.com.			600	IN	TXT	"n9rmdqaed6q0502f6t3mfj89i5"
mi.com.			600	IN	TXT	"v=spf1 include:spf_bj.mxmail.xiaomi.com include:spf_hk.mxmail.xiaomi.com  ~all"
mi.com.			65	IN	A	58.83.160.156
mi.com.			2841	IN	NS	ns4.dnsv5.com.
mi.com.			2841	IN	NS	ns3.dnsv5.com.

;; AUTHORITY SECTION:
mi.com.			2841	IN	NS	ns3.dnsv5.com.
mi.com.			2841	IN	NS	ns4.dnsv5.com.

;; ADDITIONAL SECTION:
ns3.dnsv5.com.		12665	IN	A	61.151.180.51
ns3.dnsv5.com.		12665	IN	A	117.135.170.109
ns3.dnsv5.com.		12665	IN	A	162.14.18.188
ns3.dnsv5.com.		12665	IN	A	182.140.167.191
ns3.dnsv5.com.		12665	IN	A	223.166.151.16
ns3.dnsv5.com.		12665	IN	A	14.215.150.16
ns3.dnsv5.com.		12665	IN	A	18.194.2.137
ns3.dnsv5.com.		12665	IN	A	52.77.238.92
ns3.dnsv5.com.		12665	IN	A	58.251.86.12
ns3.dnsv5.com.		12665	IN	A	59.36.120.148
ns4.dnsv5.com.		129705	IN	A	14.215.150.13
ns4.dnsv5.com.		129705	IN	A	18.235.54.99
ns4.dnsv5.com.		129705	IN	A	52.198.159.146
ns4.dnsv5.com.		129705	IN	A	59.36.120.147
ns4.dnsv5.com.		129705	IN	A	61.151.180.52
ns4.dnsv5.com.		129705	IN	A	101.226.220.12
ns4.dnsv5.com.		129705	IN	A	125.39.213.166
ns4.dnsv5.com.		129705	IN	A	162.14.18.121
ns4.dnsv5.com.		129705	IN	A	180.163.19.12
ns4.dnsv5.com.		129705	IN	A	182.254.20.44
ns4.dnsv5.com.		129705	IN	A	223.166.151.126

;; Query time: 1070 msec
;; SERVER: 192.168.64.2#53(192.168.64.2)
;; WHEN: Sat Jul 27 03:03:01 EDT 2019
;; MSG SIZE  rcvd: 717
```

**3. DNS域传送漏洞**
http://www.lijiejie.com/dns-zone-transfer-2/
DNS区域传送（DNS zone transfer）指的是一台备用服务器使用来自主服务器的数据刷新自己的域（zone）数据库，目的是为了做冗余备份，防止主服务器出现故障时 dns 解析不可用。然而主服务器对来请求的备用服务器未作访问控制，验证身份就做出相应故而出现这个漏洞。
收集dns服务器信息\手工使用nslookup命令、whois查询等手段进行对某个域名的dns服务器信息的收集,利用网络空间搜索引擎收集域名服务器信息。如（shadon、zoomeye、fofa等）,使用MASSCAN 进行端口扫描后，获取开放53号端口的dns服务器地址 http://www.freebuf.com/sectool/112583.html
```
root@kali:~# dig +short @8.8.8.8 mi.com ns
ns3.dnsv5.com.
ns4.dnsv5.com.
root@kali:~# dig +nocmd @ns4.dnsv5.com mi.com axfr
;; communications error to 14.215.150.13#53: end of file
;; communications error to 14.215.150.13#53: end of file

```
```
C:\Users\Administrator>nslookup
默认服务器:  XiaoQiang
Address:  192.168.31.1

> server ns4.dnsv5.com
默认服务器:  ns4.dnsv5.com
Addresses:  182.254.20.44
          180.163.19.12
          18.235.54.99
          162.14.18.121
          61.151.180.52
          52.198.159.146
          59.36.120.147
          223.166.151.126
          14.215.150.13
          101.226.220.12
          125.39.213.166

> ls mi.com
ls: connect: No error
*** 无法列出域 mi.com: Unspecified error
DNS 服务器拒绝将区域 mi.com 传送到你的计算机。如果这不正确，
请检查 IP 地址 182.254.20.44 的 DNS 服务器上 mi.com 的
区域传送安全设置。
```


## 子域名
https://github.com/ring04h/wydomain
在渗透测试的时候，往往主站的防御会很强，常常无从下手，那么子站就是一个重要的突破口，因此子域名是渗透测试的主要关注对象，子域名搜集的越完整，那么挖到的漏洞就可能更多，甚至漏洞的级别也会更高。常用的工具有下面这些：
**1. 子域名挖掘机Layer**

|域名	         |解析IP	         | 开放端口	 |WEB服务器	|网站状态|
|-----|-----|--------|-------|--------|
|cn.i.mi.com	|120.92.65.26	|80,443	  |-	 |80:(405) 不允许的方法
|daily.i.mi.com	|10.108.230.153	|-	      |端口未开放  |	端口未开放
|in.i.mi.com	|104.211.73.78	|80,443	|Tengine	|80:(405) 不允许的方法
|us.i.mi.com	|54.148.120.178,35.162.30.45	|80,443	|Tengine	|80:(405) 不允许的方法|

**2. subdomain lijiejie的子域名收集工具**
https://github.com/lijiejie/subDomainsBrute
```
$ python subDomainsBrute.py -t 10 i.mi.com  
  SubDomainsBrute v1.2
  https://github.com/lijiejie/subDomainsBrute

[+] Validate DNS servers                                                      
[+] Server 182.254.116.116  < OK >   Found 4                                  
[+] 4 DNS Servers found                                                      
[+] Run wildcard test
[+] Start 6 scan process
[+] Please wait while scanning ...

All Done. 4 found, 16185 scanned in 74.0 seconds.                             
Output file is i.mi.com.txt
cn.i.mi.com                   	120.92.65.26
daily.i.mi.com                	10.108.230.153
in.i.mi.com                   	104.211.73.78
us.i.mi.com                   	35.162.30.45, 54.148.120.178
```

**3. google hacking**
https://github.com/K0rz3n/GoogleHacking-Page
* 搜集域名和mail地址：
* 搜集敏感文件：`site:xxx.com filetype:doc|mdb|ini|php|asp|jsp`
* 搜集管理后台：`site:xxx.com 管理／site:xxx.com admin／site:xxx.com login`
* 搜集mail：`site:xxx.com intext:@xxx.com／intext:@xxx.com`
* 搜集敏感web路径：`site:xxx.com intitle:登录／site:xxx.com inurl:sql.php`

批量查找学校网站的后台 输入如下关键字
```

site:hdu.edu.cn  intext:管理|后台|登录|用户名|密码|验证码|系统|账号|后台管理|后台登录

intext: 把网页中的正文内容中的某个字符做为搜索条件.

例如在google里输入:intext:杭电.将返回所有在网页正文部分包含”杭电”的网页

allintext:使用方法和intext类似.

intitle: 搜索网页标题中是否有我们所要找的字符.

例如搜索:intitle:杭电.将返回所有网页标题中包含”杭电”的网页.同理allintitle:也同intitle类似.

cache: 搜索google里关于某些内容的缓存,有时候往往能找到一些好东西.

define: 搜索某个词的定义,例如搜索:define:杭电,将返回关于“杭电”的定义.

filetype: 搜索制定类型的文件，例如：filetype:doc.将返回所有以doc结尾的文件URL.

info: 查找指定站点的一些基本信息.

inurl: 搜索我们指定的字符是否存在于URL中.

例如输入:inurl:admin,将返回N个类似于这样的连接:http://xxx/admin,

常用于查找通用漏洞、注入点、管理员登录的URL

allinurl:也同inurl类似,可指定多个字符.

linkurl: 例如搜索:inurl:hdu.edu.cn可以返回所有和hdu.edu.cn做了链接的URL.

site: 搜索指定域名,如site:hdu.edu.cn.将返回所有和hdu.edu.cn有关的URL.

```
**4. 爬虫**
一些网站里面的跳转请求（也可以关注一下app）
还有就是百度，有些会在title 和 copyright信息里面出现该公司的信息
网站html源码：主要就是一些图片、js、css等，也会出现一些域名
apk反编译源码里面

## 敏感信息收集
用扫描器扫描目录，这时候你需要一本强大的字典，重在平时积累。字典越强扫描处的结果可能越多。常见有.git文件泄露，.svn文件泄露，.DB_store文件泄露，WEB-INF/web.xml泄露。目录扫描有两种方式，使用目录字典进行暴力才接存在该目录或文件返回200或者403；使用爬虫爬行主页上的所有链接，对每个链接进行再次爬行，收集这个域名下的所有链接，然后总结出需要的信息。
路径fuzz： https://github.com/ring04h/weakfilescan
敏感文件扫描: https://github.com/Mosuan/FileScan
web模糊测试: https://github.com/xmendez/wfuzz
1. github项目
GitPrey是根据企业关键词进行项目检索以及相应敏感文件和敏感文件内容扫描的工具 https://github.com/repoog/GitPrey
2. svn 泄漏
svn 文件是 subversion 的版本控制信息文件 当某个目录处于 subversion 的版本控制时，在这个目录中就会 .svn 这个文件夹，这个 .svn 文件夹中的文件就是一些版本信息文件，供 subversion 使用。由于部署上线的时候没有删除这个文件夹，导致代码泄漏。
https://i.mi.com//.svn/entries
3. 敏感文件
* DS_Store 文件泄露 https://github.com/lijiejie/ds_store_exp
* 备份文件
* WEB-INF泄露
* WEB-INF 是 Java 的 WEB 应用的安全目录。如果想在页面中直接访问其中的文件，必须通过 web.xml 文件对要访问的文件进行相应映射才能访问。
* 测试文件
* phpinfo
4. 敏感目录：网站后台目录／一些登录地址／一些接口目录

## 端口信息
https://github.com/ring04h/wyportmap
服务和安全是相对应的，每开启一个端口，那么攻击面就大了一点，开启的端口越多，也就意味着服务器面临的威胁越大。开始扫描之前不妨使用telnet先简单探测下某些端口是否开放，避免使用扫描器而被封IP，扫描全端口一般使用Nmap，masscan进行扫描探测，尽可能多的搜集开启的端口好已经对应的服务版本，得到确切的服务版本后可以搜索有没有对应版本的漏洞。
端口渗透过程中我们需要关注几个问题：
* 端口的banner信息
* 端口上运行的服务
* 常见应用的默认端口

|端口号     |  端口服务/协议简要说明     |      关于端口可能的一些渗透用途 |
|-----|---------|------------|
|tcp 20,21    |ftp 默认的数据和命令传输端口[可明文亦可加密传输]  |允许匿名的上传下载,爆破,嗅探,win提权,远程执行(proftpd 1.3.5),各类后门(proftpd,vsftp 2.3.4)|
|tcp 22   | ssh[数据ssl加密传输]    |可根据已搜集到的信息尝试爆破,v1版本可中间人,ssh隧道及内网代理转发,文件传输,等等…常用于linux远程管理…|
|tcp 23    |telnet[明文传输]  |  爆破,嗅探,一般常用于路由,交换登陆,可尝试弱口令,也许会有意想不到的收获|
|tcp 25    |smtp[简单邮件传输协议,多数linux发行版可能会默认开启此服务]   | 邮件伪造,vrfy/expn 查询邮件用户信息,可使用smtp-user-enum工具来自动跑|
|tcp/udp 53    |dns[域名解析]   | 允许区域传送,dns劫持,缓存投毒,欺骗以及各种基于dns隧道的远控|
|tcp/udp 69    |tftp[简单文件传输协议,无认证]   | 尝试下载目标及其的各类重要配置文件
|tcp 80-89,443,8440-8450,8080-8089    |web[各种常用的web服务端口]  |  各种常用web服务端口,可尝试经典的top n,vpn,owa,webmail,目标oa,各类java控制台,各类服务器web管理面板,各类web中间件漏洞利用,各类web框架漏洞利用等等……
|tcp 110    |[邮局协议,可明文可密文]  |  可尝试爆破,嗅探
|tcp 137,139,445    |samba[smb实现windows和linux间文件共享,明文]   | 可尝试爆破以及smb自身的各种远程执行类漏洞利用,如,ms08-067,ms17-010,嗅探等……
|tcp 143   | imap[可明文可密文]  |  可尝试爆破
|udp 161    |snmp[明文]   |爆破默认团队字符串,搜集目标内网信息
|tcp 389    |ldap[轻量级目录访问协议]   | ldap注入,允许匿名访问,弱口令
|tcp 512,513,514   | linux rexec   | 可爆破,rlogin登陆
|tcp 873    |rsync备份服务  |  匿名访问,文件上传
|tcp 1194    |openvpn   | 想办法钓vpn账号,进内网
|tcp 1352   | Lotus domino邮件服务   | 弱口令,信息泄漏,爆破
|tcp 1433    |mssql数据库   | 注入,提权,sa弱口令,爆破
|tcp 1521    |oracle数据库 |   tns爆破,注入,弹shell…
|tcp 1500   | ispmanager 主机控制面板  |  弱口令
|tcp 1025,111,2049    |nfs    |权限配置不当
|tcp 1723    |pptp    |爆破,想办法钓vpn账号,进内网
|tcp 2082,2083    |cpanel主机管理面板登录    |弱口令
|tcp 2181   | zookeeper    |未授权访问
|tcp 2601,2604    |zebra路由    |默认密码zerbra
|tcp 3128   | squid代理服务   | 弱口令
|tcp 3312,3311   | kangle主机管理登录   |弱口令
|tcp 3306   | mysql数据库  |  注入,提权,爆破
|tcp 3389   | windows rdp远程桌面   | shift后门[需要03以下的系统],爆破,ms12-020[蓝屏exp]
|tcp 4848   | glassfish控制台   | 弱口令
|tcp 4899   | radmin远程桌面管理工具,现在已经非常非常少了 |   抓密码拓展机器
|tcp 5000   | sybase/DB2数据库   | 爆破,注入
|tcp 5432   | postgresql数据库   | 爆破,注入,弱口令
|tcp 5632   | pcanywhere远程桌面管理工具    |抓密码,代码执行,已经快退出历史舞台了
|tcp 5900,5901,5902    |vnc远程桌面管理工具   | 弱口令爆破,如果信息搜集不到位,成功几率很小
|tcp 5984   | CouchDB  | 未授权导致的任意指令执行
|tcp 6379  |  redis未授权 |   可尝试未授权访问,弱口令爆破
|tcp 7001,7002  |  weblogic控制台   | java反序列化,弱口令
|tcp 7778  |  kloxo   | 主机面板登录
|tcp 8000   | Ajenti主机控制面板   | 弱口令
|tcp 8443   | plesk主机控制面板   | 弱口令
|tcp 8069   | zabbix   | 远程执行,sql注入
|tcp 8080-8089   | Jenkins,jboss  |  反序列化,控制台弱口令
|tcp 9080-9081,9090   | websphere控制台  |  java反序列化/弱口令
|tcp 9200,9300  |  elasticsearch   | 远程执行
|tcp 10000   | webmin linux主机web控制面板入口   | 弱口令
|tcp 11211   | memcached   | 未授权访问
|tcp 27017,27018   | mongodb  |  爆破,未授权访问
|tcp 3690   | svn服务  |  svn泄露,未授权访问
|tcp 50000   | SAP Management Console   | 远程执行
|tcp 50070,50030  |  hadoop    |默认端口未授权访问

## WAF检测
* waf00f：是kali下的识别WAF的老工具 https://github.com/Ekultek/WhatWaf `waf00f mi.com`
* 从乌云镜像站、CNVD搜集网站历史漏洞
* SQLMAP自带的WAF识别功能，我移植出来了，可以自定义新规则。发布在T00ls https://www.t00ls.net/thread-46639-1-1.html
* 使用云悉也可以查询出WAF
* 输入一个错误的页面，查看返回的头部信息或者body信息

## 小结
通过搜索引擎获取系统管理页面，直接越权访问；
通过github直接找到管理后台账号密码；
通过目录／文件扫描直接得到系统信息（ip、管理员账号密码）连入服务器；

# 0x02 信息处理
1. 信息整理
分类：
* 哪些网站功能类似；
* 哪些网站可能使用的同一模版；
* 哪些网站有waf（这个一般在url中标明就好）；
* 哪些网站能登录（注册的账号也一定要记住，最好可以准备两个手机号，两个邮箱方便注册）；
* 哪些网站暴露过哪些类型的漏洞（这个只能去乌云上面找）；
* 网站目前有哪些功能（这个稍微关注一下网站公告，看最近是否会有业务更迭）；

2. 漏洞整理


# 0x03 漏洞挖掘
owasp top 10、逻辑
1. 首先我们需要对一个网站／app有一个了解要知道它的功能点有哪些
2. 其次我们要分析这个网站／app里面的请求哪些是我们可以控制的参数，这些地方就是漏洞经常出没的点
3. 最后就是分析逻辑

例：”我们买东西”
* 首先我们要选择：筛选涉及查询（是否可以SQL注入）
* 加入购物车：商品数量是否可以为负

* 询问商家：
跳转客服系统，跳转url中是否含有用户参数
xss打客服cookie
钓鱼+社工

* 下单：
填地址，涉及插入（注入）、xss
修改单价
修改总额（这里说明一下修改总额：情况1，就是我们可能会遇到可以使用优惠卷的情况，比如我们买了100的东西只能使用5块的优惠价，但是我有一张50的优惠卷是否可以使用；情况2，打折我们是否可以修改打折的折扣；情况3，我们是否可以修改运费，将运费改为负数；情况n）

* 备注：xss，sql注入

* 电子票据：会写抬头

* 支付：
传输过程中是否可以修改，如果是扫描二维码支付，我们可以分析一下二维码中的请求url看是否可以修改以后重新生成二维码（这里不讨论后面具体了支付了，因为微信和支付宝）

* 订单完成：是否可以遍历订单
* 评价：注入、上传图片、xss
