---
title: QQ数据库的加密与解密
date: 2019-02-22 18:35:27
categories:
- 加密解密
tags:
- 密码
- QQ
- 数据库
---

# qq数据库采用简单加密——异或加密

## 数据获取：
DENGTA_META.xml—IMEI:867179032952446
databases/2685371834.db——数据库文件

## 解密方式：
明文msg_t   密文msg_Data  key：IMEI
msg_t = msg_Data[i]^IMEI[i%15]

## 实验：
```
import sqlite3

IMEI = '867179032952446'
conn = sqlite3.connect('2685371834.db')
c = conn.cursor()

def _decrypt(foo):
    substr = ''
    #print(len(foo))
    for i in range(0,len(foo)):
        substr += chr(ord(foo[i]) ^ ord(IMEI[i%15]))
    return substr

#rem = c.execute("SELECT uin, remark, name FROM Friends")
Msg = c.execute("SELECT msgData, senderuin, time FROM mr_friend_0FC9764CD248C8100C82A089152FB98B_New")

for msg in Msg:
    uid = _decrypt(msg[1])
    print("\n"+uid+":")
    try:
        msgData = _decrypt(msg[0]).decode('utf-8')
        print(msgData)
    except:
        pass
```
## 结果
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1552728077/qq.png)
