---
title: 自动化获取nvram配置
date: 2021-01-08 16:27:26
tags:
- Netgear
- UPnP
- NVRAM
- 固件模拟
categories:
- IOT
description: 还记得固件仿真吗？先试着快速解决nvram
---

ARMX作者说，nvram的内容必须从正在运行的设备中提取。
一种方法是转储包含nvram数据的mtdblock， /proc/mtd可能有助于识别哪个mtdblock包含nvram。
另一种方法是，如果您可以通过UART进行命令行访问（当然可以访问实际的硬件），某些固件会提供nvram命令，运行“ nvram show”也可以获取nvram内容。
https://github.com/therealsaumil/armx/issues/4

知道创宇的研究人员说，nvram配置，可以查看对应的汇编代码逻辑（配置的有问题的话很容易触发段错误）。

我需要无需硬件自动化的处理大批设备的nvram配置，上面两种方法都无法适用。但我发现Netgear的nvram配置有这两个te'd

* upnp等二进制程序通过nvram_match来匹配nvram变量与预期值
* libnvram在data段存储了设备的默认nvram配置，**数据段**（data segment）通常是指用来存放[程序](https://zh.wikipedia.org/wiki/%E7%A8%8B%E5%BA%8F)中已[初始化且不为0](https://zh.wikipedia.org/w/index.php?title=%E5%88%9D%E5%A7%8B%E5%8C%96%E4%B8%94%E4%B8%8D%E4%B8%BA0&action=edit&redlink=1)的[全局变量](https://zh.wikipedia.org/wiki/%E5%85%A8%E5%B1%80%E5%8F%98%E9%87%8F)的一块内存区域。数据段属于[静态内存分配](https://zh.wikipedia.org/wiki/%E9%9D%99%E6%80%81%E5%86%85%E5%AD%98%E5%88%86%E9%85%8D)。

于是根据这两个事实做了两个实验：

## match函数

该函数的逻辑如下，a1为要查询的key，a2为待比较的对应value，调用nvram_get获得nvram中a1的value，然后和a2比较，相同的话返回1。

```
const char *__fastcall acosNvramConfig_match(int a1, const char *a2)
{
  const char *v2; // r4
  const char *result; // r0
  int v4; // [sp+0h] [bp-1008h]

  v2 = a2;
  result = (const char *)j_nvram_get(a1, &v4, 4096);
  if ( result )
    result = (const char *)(strcmp(result, v2) == 0);
  return result;
}
```

在upnp二进制程序汇编代码中，调用acosNvramConfig_match来比较nvram
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610094619/nvram/image_24.png)
我做出了一个假设：所有a2都是能够使程序正常运行的nvram值，现在想要获取它。编写IDA脚本如下：

```
def GetAddr(func_name):
    func_list = Functions()
    for func in func_list:
        name = GetFunctionName(func)
        if func_name == name:
            print(name,hex(func))
            func_addr=func
            return func_addr

func_addr = GetAddr('acosNvramConfig_match')
#func_addr=0xa3d4

for x in XrefsTo(func_addr,flags=0):
    print "XrefsTo nvram-match func addr: %s"%hex(x.frm)
    match_addr = x.frm
    val_addr = PrevHead(match_addr)
    key_addr = PrevHead(val_addr)
    if GetMnem(key_addr) == 'LDR':
        instr = GetDisasm(prevaddr)
        #print('LDR instruction: %s'%instr)
        addr = GetOperandValue(key_addr,1)
        key = GetString(Dword(addr))
        print('nvram key: %s'%key)
    if GetMnem(val_addr) == 'LDR':
        instr = GetDisasm(prevaddr)
        #print('LDR instruction: %s'%instr)
        addr = GetOperandValue(val_addr,1)
        val = GetString(Dword(addr))
        print('nvram value: %s'%val)
```

1. GetAddr(func_name) 根据函数名获得地址，这里获得了'acosNvramConfig_match'的地址0xa3d4；
2. 找到所有引用过该函数的地址，并且提取作为参数的数据。获取到函数的引用非常的简单，只需要使用XrefsTo()这个API函数就能达到我们的目的。
3. value是调用match函数的前一条指令；key是调用match函数的前两条指令；操作码都是LDR;
4. 使用GetOperandValue() 这个指令得到第二个操作数的值。注意该值存放的是“存放字符串地址”的地址
5. 使用Dword(addr)获取“存放字符串地址”，使用GetString()这个API函数从该偏移提取字符串

粘贴部分结果，有大量的重复，还有许多键值不存在，假设不成立。

```
('acosNvramConfig_match', '0xa3d4L')
XrefsTo nvram-match func addr: 0xc940L
nvram key: qos_bw_set_sel
nvram value: 1
XrefsTo nvram-match func addr: 0xc9b4L
nvram key: qos_bw_enable
nvram value: 1
XrefsTo nvram-match func addr: 0xfbd0L
nvram key: wlg_band
nvram value: 2.4G
XrefsTo nvram-match func addr: 0xfc84L
nvram value: 5G
XrefsTo nvram-match func addr: 0xff70L
nvram key: wlg_band
nvram value: 2.4G
nvram value: static
XrefsTo nvram-match func addr: 0x13d2cL
nvram key: board_id
nvram value: U12H127T00_NETGEAR
```

## NVRAM默认配置

如上所述，libnvram.so中data段存放着默认配置
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610094620/nvram/image_23.png)
利用IDApython获取该区域存放的键值，注意：该区域并不存放字符串，而是存放“存放字符串地址处”的地址，所以也要通过Doword来获取实际地址

```
import idautils
for seg in idautils.Segments():
    if SegName(seg) == '.data':
        start = idc.SegStart(seg)
        end = idc.SegEnd(seg)
        print idc.SegName(seg),start,end
        while(start!=end):
            key = GetString(Dword(start))
            if key != None and key != '0':
                start += 4
                val = GetString(Dword(start))
                if 'upnp' in key:
                    print('%s=%s'%(key,val))
            start += 4
```

这里我们只关注有upnp特征的键值对

```
.data [77868 94004](tel:7786894004)
upnp_enable=1
upnp_turn_on=1
upnp_advert_period=30
upnp_advert_ttl=4
upnp_portmap_entry=0
upnp_duration=3600
upnp_DHCPServerConfigurable=1
```

另外再补充几个与网络有关的配置

```
friendly_name=Netgear
lan_hwaddr=AA:BB:CC:DD:EE:FF
lan_ipaddr=192.168.2.2
```

使用这个配置成功仿真~


## 一些IDApython使用方法

蒸米写的：https://wooyun.js.org/drops/IDAPython%20%E8%AE%A9%E4%BD%A0%E7%9A%84%E7%94%9F%E6%B4%BB%E6%9B%B4%E6%BB%8B%E6%B6%A6%20part1%20and%20part2.html
https://cartermgj.github.io/2017/10/10/ida-python/
https://gitee.com/it-ebooks/it-ebooks-2018-04to07/raw/master/IDAPython%20%E5%88%9D%E5%AD%A6%E8%80%85%E6%8C%87%E5%8D%97.pdf
https://www.0xaa55.com/thread-1586-1-1.html
https://wizardforcel.gitbooks.io/grey-hat-python/content/43.html
