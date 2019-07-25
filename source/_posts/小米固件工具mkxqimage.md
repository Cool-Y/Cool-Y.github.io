---
title: 小米固件工具mkxqimage
date: 2019-03-16 14:57:56
tags:
- 小米
- 文件格式
- SSH
categories:
- IOT
---
# 小米固件工具mkxqimage

小米自己改了个打包解包固件的工具，基于 trx 改的（本质上还是 trx 格式），加了 RSA 验证和解包功能，路由系统里自带：
```
Usage:
mkxqimg [-o outfile] [-p private_key] [-f file] [-f file [-f file [-f file ]]]
        [-x file]
        [-I]
```

## 固件打包
小米官方在打包固件时用RSA私钥计算出固件的RSA签名，小米路由器下载固件后用RSA公钥来验证RSA签名，有效地防止固件被篡改。

## 固件解包
固件工具mkxqimage完成对固件的解包，在解包前先检查Checksum是否正确，然后利用RSA公钥/usr/share/xiaoqiang/public.pem检查RSA签名，这两个步骤通过后，根据[0x0C]的固件类型，以及[0x10]、[0x14]、[0x18]和[0x1C]的4个偏移量拆分固件。

## 固件更新签名校验
小米路由器进行固件更新时同样会进行签名校验，文件/usr/share/xiaoqiang/public.pem是它的公钥，用来校验签名正确与否。正因为这样，黑客如果想在不拆机的前提下刷入已植入木马的固件，只有两条路可走，一是通过入侵、社工或破解得到对应的私钥，然后对修改后的固件进行签名再刷入；二是通过漏洞，挖掘新的漏洞或者刷入有漏洞的旧版固件，然后再通过漏洞利用得到root shell进而刷入任意固件。一般来讲，第一条路是很难的，而为了堵住第二条路，可以通过限制降级来实现。

由此可见，在限制降级的前提下，在固件更新时进行签名校验，能有效地防止路由器被植入木马。

## [固件格式](http://www.iptvfans.cn/wiki/index.php/%E5%B0%8F%E7%B1%B3%E8%B7%AF%E7%94%B1%E5%99%A8%E5%9B%BA%E4%BB%B6%E5%88%86%E6%9E%90)
路由固件的格式，基本是基于 openwrt 的 trx 这个简单的二进制文件格式
```
48 44 52 30 63 D4 11 03 FE 3D 1A FD 05 00 02 00
20 00 00 00 20 00 FE 00 00 00 00 00 00 00 00 00
FF 04 00 EA 14 F0 9F E5 14 F0 9F E5 14 F0 9F E5
```
第1～4字节：ASCII字符串“HDR0”，作为固件的标识；
第5～8字节：4字节整型数0x0311D464，表示固件的大小：51500132字节；
第9~12字节：固件的检查和；
第13～14字节：0x0005，表示固件中包含哪些部分；
第15～16字节：0x0002，表示固件格式版本号；
第17～20字节：0x00000020，表示固件第一部分在整个固件中的偏移量，0.4.85固件的第一部分是brcm4709_nor.bin，也就是Flash中除0xfe0000-0xff0000的board_data外的全镜像；
第21～24字节：0x00FE0020，表示固件第二部分在整个固件中的偏移量，0.4.85固件的第二部分是root.ext4.lzma，也就是硬盘中128M固件的压缩包；
第33字节开始是固件的正式内容开始。

## 小米开启ssh工具包
使用mkxqimage解包
（现在会提示秘钥不存在）
```
error fopen public key
Image verify failed, not formal image
```

如果能解包应该可以得到脚本文件upsetting.sh

```
#!/bin/sh
nvram set ssh_en=1
nvram set flag_init_root_pwd=1
nvram commit
```
执行脚本文件upsetting.sh后，将ssh_en设置为1，同时设置了flag_init_root_pwd项。当正式启动时，/usr/sbin/boot_check脚本检测到flag_init_root_pwd=1时，自动修改root用户密码，具体脚本为：
```
flg_init_pwd=`nvram get flag_init_root_pwd`
if [ "$flg_init_pwd" = "1" ]; then
	init_pwd=`mkxqimage -I`
	(echo $init_pwd; sleep 1; echo $init_pwd) | passwd root
	nvram unset flag_init_root_pwd
	nvram commit
fi
```
初始密码是mkxqimage -I的结果，实际是根据路由器的序列号计算得到。路由器的序列号印在底盖上，12位数字，如：561000088888

初始密码计算算法为：

`substr(md5(SN+"A2E371B0-B34B-48A5-8C40-A7133F3B5D88"), 0, 8)`

***A2E371B0-B34B-48A5-8C40-A7133F3B5D88*** 为分析mkxqimage得到的salt
