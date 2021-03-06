---
title: DataCon Coremail邮件安全第三题 Writeup

date: 2020-10-16 11:07:33
tags:
- 钓鱼邮件
- phishing email
categories:
- 杂七杂八
description: 研一的时候参加了第一届datacon，可惜因为课程任务太重了，最后连答案都没提交。今年和研一两位师弟师妹组队参加，本以为又要躺过去了，最后被两位的热情感染，完成了比赛还取得不错的成绩，也算是完成了研究生阶段的一个小遗憾。我之前没做过数据分析也没接触过邮件安全，借这次赛题好好的补了一课，第一题是识别发件人伪造，第二题是垃圾邮件分类，第三题是识别威胁邮件，全部是真实数据，难度层层递进。
---

## 赛题理解

### 目标

> 在真实的企业网络环境中，一些攻击者总能想方设法绕过邮件检测引擎，使攻击邮件抵达员工的收件箱，最终达到窃取用户登录凭证等目的。与此同时，企业网络安全管理团队的精力十分有限，不可能实现对企业的全部邮件进行逐一审查。

> 如果你是一家企业的邮件安全负责人，能否基于数据分析，利用长达三个月的企业邮件服务器日志摘要信息，设计检测模型，输出一批威胁程度较高的邮件，以便于后续的人工审查。请注意：检测模型不允许使用第三方威胁情报，检测系统必须能够离线运行。


从赛题说明中，我们可以提取出几个关键词：邮件、窃取用户凭证、威胁程度、离线运行，最终目的是从邮件通信日志中筛选出钓鱼邮件（窃取用户登录凭证）。

### 数据

> 约80万封邮件通信日志，赛事主办方已经对数据进行了脱敏和匿名化处理。

> 提示：根据既往经验知识，威胁程度较高的邮件规模约在2千至2万左右。

主办方给了威胁邮件的大致数量范围，邮件通信日志与第一题真实的邮件格式不同，每一封邮件都是json格式的数据，只保留了8个字段，而且做了匿名化处理。

```
* rcpt：收信人邮箱地址   --->  [salt+hash]@[salt+hash替换掉敏感域名，其它保留].[真实TLD]
* sender：发件人邮箱地址    --->  同上
* ip：企业邮箱用户登录ip   --->  经过映射处理，不是真实的ip地址，但保留子网关系
* fromname：发信人名称  --->  对于白名单关键词（比如admin，hr，管理员，经理等）进行保留。除了白名单的其它部分salt+hash
* url：直接从邮件正文、subject、附件、fromname中提取出来的url   ---> [真实协议]://hash+salt替换掉敏感域名.真实TLD/真实参数
* @timestamp：时间戳
* region：企业邮箱用户登录ip所在地区
* authuser：收信时False，发信时True，注意企业邮箱域内互发的话是只有一条发信记录
* tag：邮件编号，提交答案需要用到
```

### 提交规则

主办方给的方法很简单，每一封邮件均有字段tag，结果只需要每行一个威胁邮件的tag，换行使用`\n`

### 评分

> 比赛过程中排行榜展示每位选手的F1-score，未提交答案F1-score视为0，比赛结束后，每位选手的得分由`min-max归一化*100`计算得出，保留1位小数（四舍五入）

最终得分不仅取决于自己的F1-score，还取决于所有选手的整体成绩。另外利用F1-score，我们还能推测出这80万封邮件中大致的威胁邮件数量，后续再说。

## 解题思路

在初步浏览了一些邮件日志内容后，我们将目标锁定为寻找钓鱼邮件的数量。首先需要知道钓鱼邮件是什么，具备哪些特征。

### 1. 使用短链接

短链接就是将较长的网址，通过特定的算法转换为简短的网址字符串。用户无法通过短链接地址直接看出点击这个短链接地址后究竟会打开什么样的网站。
常见的有：`t.cn`、  `bit.ly`、 `bit.do`、  `u.to`、 `url.cn`

### 2. 使用十六进制IP地址编码格式进行混淆

网络攻击者正在不断发展其工具、策略和技术，以逃避垃圾邮件检测系统。 一些垃圾邮件活动非常依赖电子邮件信息中的混淆URL。其中就有使用了URL主机名部分中使用的十六进制IP地址编码格式来逃避检测。
从技术上讲，IP地址可以用多种格式表示，因此可以在URL中使用，如下所示：

* **https://216.58.199.78**
    点分十进制IP地址，此示例使用Google.com的IP
* **https://0330.0072.0307.0116**
    八进制IP地址，将每个十进制数字转换为八进制
* **https://0xD83AC74E**
    十六进制IP地址，将每个十进制数字转换为十六进制
* **https://3627730766**
    整数或DWORD IP地址，将十六进制IP转换为整数

浏览器将自动将十六进制或其他IP格式转换为十进制的IP地址。

### 3. 邮件钓鱼测试工具固有特征

PhEmail是基于python编写的一款网络钓鱼邮件测试工具。PhEmail可以同时向多个用户发送钓鱼邮件，并记录点击的用户的邮箱和IP等信息。PhEmail可以通过Google收集邮箱，完成邮箱收集工作。
收集邮箱后钓鱼邮件发送常用参数：`-w 钓鱼网站url地址，发送后会自动添加index.php?email=等内容`
钓鱼邮件中的url链接伪造时添加email地址并进行编码，通过钓鱼网站中php文件代码来识别email并记录log文件中。php可以进行重定向到其他网站。

### 4. 冒充管理员等身份

对于企业用户来说，OA钓鱼邮件是最具危险性的钓鱼邮件。攻击者冒充系统管理员发送邮件，以邮箱升级、邮箱停用等理由诱骗企业用户登录钓鱼网站，并进而骗取企业员工的帐号、密码、姓名、职务等信息。
钓鱼邮件经常伪装的发件人身份有以下几个主要类型：

* 冒充系统管理员，以系统升级、身份验证等为由，通过钓鱼网站等方式骗取企业员工的内网帐号密码或邮箱帐号密码。
* 冒充特定组织，如协会、机构、会议组织者或政府主管部门等身份发送邮件，骗取帐号密码或钱财。
* 冒充客户或冒充自己，即攻击者会冒充企业客户或合作方对企业实施诈骗，或者是攻击者冒充某企业员工对该企业的客户或合作方实施诈骗。当然也有可能 是冒充某个企业的管理者对企业员工实施诈骗。

从fromname（发信人名称）中获得的常见名称有：admin、support、安全、service、管理员等。


### 5. 同形异义词攻击

同形异义字是利用IDN中一些非拉丁字符语种的字母与拉丁字符非常相似，字面看很难区分的特性，找到对应的字符来实现钓鱼攻击。例如16ვ.com(U+10D5)、16ဒ.com (U+1012)、16ҙ.com (U+0499) 都在一定程度上和163.com有相似性，基于一些开放的https证书服务这些域名还能取得相应的证书，进一步增加钓鱼成功的可能性。
Punycode是RFC 3492标准设计的编码系统，用于把Unicode转换为可用的DNS系统的编码，比如16ҙ.com就会被转成**xn--16-8tc.com**，这在一定程度上可以防止IDN欺骗。

### 6. URL跳转

使用URL跳转可以突破钓鱼软件检测系统。这类钓鱼软件检测系统在检测是否是钓鱼网站或者恶意系统的时候，检测的是URL，而并非网站的内容。比如，从qq邮箱打开一个URL的时候，会弹出一个网页提示。但并不是所以的网站都会提示，一些知名网站是不可能做钓鱼网站的，所以邮箱就不会拦截，也就是说，当邮箱碰到不认识的网站的时候才会进行提示。
 这样攻击者就可以利用URLt跳转来躲过恶意检测。比如：**http://www.baidu.com/page?url=http://www.evil.com**

## 参考
2016中国企业邮箱安全性研究报告 https://www.anquanke.com/post/id/85416
PhEmail https://github.com/Dionach/PhEmail
微软：最新钓鱼技术2019总结 https://www.4hou.com/posts/A9oz
[译] APT分析报告：02.钓鱼邮件网址混淆URL逃避检测 https://blog.csdn.net/Eastmount/article/details/108728139
2017中国企业邮箱安全性 研究报告 http://zt.360.cn/1101061855.php?dtid=1101062514&did=491163339
基于URL跳转与XSS组合利用的钓鱼分析 https://xz.aliyun.com/t/6303
IDN Spoof漏洞自动化挖掘 https://blog.lyle.ac.cn/2018/12/08/idnfuzz/
APT杂项篇一种老旧，但却防不胜防的钓鱼攻击（Punycode 钓鱼攻击）https://www.codenong.com/cs106406317/
钓鱼网站也在使用https加密，如何识别钓鱼网站？ https://www.freebuf.com/company-information/208790.html
恶意邮件智能监测与溯源技术研究 https://www.anquanke.com/post/id/172046#h2-0
钓鱼邮件的投递和伪造 https://xz.aliyun.com/t/6325#toc-0、
用机器学习检测钓鱼网站 http://blog.hubwiz.com/2019/09/17/detect-phishing-url/
