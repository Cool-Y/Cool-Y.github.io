---
title: 利用itchat定时转发微信消息
date: 2019-03-23 19:48:46
tags:
- itchat
- 微信
categories:
- 杂七杂八
description: 看了这篇文章，女朋友还会问你为什么不给她发微信吗？
---
我们实验室有个光荣传统，每天早上起床叫醒我的不是闹钟，而是群里雷打不动的安全新闻（其实我免提醒了2333）
而这个发送新闻的人，一代一代的传承，我没想到竟然有一天会落在我头上，哭了o(╥﹏╥)o
为了不暴露我的起床时间，同时能保质保量的完成任务，我决定做个机器人帮我完成。
这就是这片po文的由来啦！
# 大杀器itchat
## introduction
先来一段[itchat](https://itchat.readthedocs.io/zh/latest/)的官方介绍吧
>itchat是一个开源的微信个人号接口，使用python调用微信从未如此简单。
>使用不到三十行的代码，你就可以完成一个能够处理所有信息的微信机器人。
>当然，该api的使用远不止一个机器人，更多的功能等着你来发现，比如这些。
>该接口与公众号接口itchatmp共享类似的操作方式，学习一次掌握两个工具。
>如今微信已经成为了个人社交的很大一部分，希望这个项目能够帮助你扩展你的个人的微信号、方便自己的生活。

实际上，itchat是对微信网页端的爬虫，所以，网页端可以实现的功能都有，那么，我想要的定时群发微信消息，自然不在话下！

## 初步尝试
- 安装
```
pip install itchat
```
- 一个简单实例：实现给文件传输助手发送消息

```
import itchat
itchat.auto_login()
itchat.send('Hello, filehelper', toUserName='filehelper')
```

# 实现定时转发
这个的实现需要注册msg_register,逻辑很简单，当收到指定群里的指定消息时，将消息转发到另一个群。
```
import itchat
from datetime import datetime
import time
import re
import threading
from itchat.content import TEXT
from itchat.content import *
from apscheduler.schedulers.blocking import BlockingScheduler

@itchat.msg_register([TEXT], isFriendChat=True, isGroupChat=True, isMpChat=True)
def getContent(msg):
    global g_msg
    groups = itchat.get_chatrooms(update = True)
    for g in groups:
        #print(g['NickName'])
        if g['NickName'] == '被转发的群名':
            from_group = g['UserName']
    if '每日安全简讯' in msg['Content']:
        print("get message from " + msg['FromUserName'])
        if msg['FromUserName'] == from_group:
            g_msg = msg['Content']
            print('成功获得群消息，等待转发')
            print(int(time.strftime("%H%M%S")))
            while(1):
                if int(time.strftime("%H%M%S")) > 80000:
                    SendMessage(g_msg,'发送的对象群名')
                    g_msg = ''
                    break

def SendMessage(context,gname):
    itchat.get_chatrooms(update = True)
    users = itchat.search_chatrooms(name=gname)
    userName = users[0]['UserName']
    itchat.send_msg(context,toUserName=userName)
    print("\n发送时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n" "发送到：" + gname + "\n" + "发送内容：" + context + "\n")
    print("*********************************************************************************")

if __name__ == '__main__':
    itchat.auto_login(hotReload=True,enableCmdQR=2)
    itchat.run(blockThread=False)
```

# 添加周期防掉线
据说每三十分钟发送一次消息可防止网页端微信掉线~~
```
def loop_send():
    nowTime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    context = '现在是北京时间 :\n'+ nowTime +'\n\n我们还活着'
    itchat.get_chatrooms(update = True)
    users = itchat.search_friends(name=u'chengkun')
    userName = users[0]['UserName']
    itchat.send_msg(context,toUserName=userName)

if __name__ == '__main__':
    sched = BlockingScheduler()
    sched.add_job(loop_send,'interval',minutes=30)
    sched.start()
```

# 把程序放在服务器上
我是在腾讯云有个服务器，因为自己的电脑不可能时时刻刻开机，所以就放在服务器上，方法是：
```
sudo nohup python -u auto_Send.py >> auto_Send.log 2>&1 &
```
- 使用nohup可以让程序在后台运行
- 然后将日志输出到auto_Send.log，方便我们后期出bug了排错
- -u可以防止输出到python缓冲区

# 遇到的坑
## 线程阻塞问题
这里有两个线程，一个是定时转发，一个是循环发送，因此要设置为itchat.run(blockThread=False)以及sched = BlockingScheduler()否则会卡在某个方法。
## 找不到群组
这是因为users = itchat.search_chatrooms(name=gname)，在搜索的是你保存到通讯录的群组。
## 二维码显示不全
itchat.auto_login(hotReload=True,enableCmdQR=2)，需要设置为2
