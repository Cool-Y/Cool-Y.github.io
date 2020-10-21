---
title: PE文件格式学习
date: 2019-05-13 20:37:00
tags:
- PE
- 文件格式
categories:
- 二进制
---

# PE文件格式
PE(Portable Executable)是Win32平台下可执行文件遵守的数据格式。常见的可执行文件（如exe和dll）都是典型的PE文件。PE文件格式其实是一种数据结构，包含Windows操作系统加载管理可执行代码时所必要的信息，如二进制机器代码、字符串、菜单、图标、位图、字体等。PE文件格式规定了所有这些信息在可执行文件中如何组织。**在程序被执行时，操作系统会按照PE文件格式的约定去相应地方准确定位各种类型的资源，并分别装入内存的不同区域。**
PE文件格式把可执行文件分成若干个数据节（section），不同资源被存放在不同的节中，一个典型的PE文件中包含的节如下：
- ``.text``     由编译器产生，存放着二进制的机器代码，也是反汇编和调试的对象
- ``.data``     初始化的数据块，如宏定义、全局变量、静态变量等
- ``.idata``    可执行文件所使用的动态链接库等外来函数与文件信息
- ``.rsrc``     存放程序的资源，如图标、菜单等
除此之外，还有可能有``.reloc``,``.edata``,``.tls``,``.rdata``

# 0x01 PE文件与虚拟内存之间的映射
## 虚拟内存
Windows的内存可以被分为两个层面：物理内存和虚拟内存。其中，物理内存比较复杂，需要进入Windows内核级别ring0才能看到。通常，在用户模式下，我们用调试器看到的都是虚拟内存。
如果我们把这看成银行，那么就很好理解了。
- 进程相当于储户
- 内存管理器相当于银行
- 物理内存相当于钞票
- 虚拟内存相当于存款

## 映射关系
1. 在漏洞挖掘中,经常需要的两种操作：
- 静态反编译工具看到的是PE文件中某条指令的位置是相对与磁盘而言的，就是所谓的 **文件偏移** ，我们可能还需要知道这条指令在内存中的位置，这个位置就是虚拟内存地址(VA)
- 反过来，在调试时看到的某条指令的地址是 **虚拟内存地址（VA）**，也就是我们需要回到PE文件中找到这条指令对应的机器码

2. 几个重要概念
- 文件偏移地址(File Offset)：
数据在PE文件中的地址叫做文件偏移地址,可以理解为就是文件地址。这是文件在磁盘上存放相对与文件开头的偏移。
- 装载基址(Image Base):
PE装入内存时的基地址。默认情况下，EXE文件在内存中对应的基地址是``0x00400000``,DLL文件是``0x10000000``。这些位置可能通过编译选项修改
- 虚拟内存地址(Virtual Address,VA )：
PE文件中的指令装入内存后的地址。
- 相对虚拟地址(Relative Virtual Address, RVA)：
相对虚拟地址是内存地址相对于映射基址的偏移量。

3. 虚拟内存地址，装载基址，相对虚拟内存地址三者之间的关系:
>VA = Image Base + RVA

4. 文件偏移地址与相对虚拟地址：
文件偏移地址是相对于文件开始处0字节的偏移,RVA(相对虚拟地址)则是相对于装载基址0x00400000处的偏移.由于操作系统在装载时“基本”上保持PE中的数据结构，所以文件偏移地址和RVA有很大的一致性。（不是全部相同）
PE文件中的数据按照磁盘数据标准存放，以0x200为基本单位进行组织。当一个数据节(stction)不足0x200字节时，不足的地方将用0x00填充，当一个数据节超过0x200时，下一个0x200块将分配给这个节使用。所以PE数据节大小永远是0x200的整数倍
当代码装入后，将按照内存数据标准存放，并以0x1000字节为基本的存储单位进行组织，不足和超过的情况类似上面。因此，内存中的节总是0x1000的整倍数。
由于内存中数据节相对于装载基址的偏移量和文件中数据节的偏移量有上述差异，所以进行文件偏移到内存地址之间的换算时，还要看所转换的地址位于第几个节内:
>文件偏移地址 = 虚拟内存地址(VA) - 装载基址(Image Base) - 节偏移
​ = RVA - 节偏移

5. 工具
[LordPE DLX增强版(2017..6.08)](https://tools.pediy.com/win/PE_tools/Lordpe/LPE-DLX.rar)
[Resource Hacker 3.4.0](https://tools.pediy.com/win/Resource/Resource%20Hacker/reshhack3.4.zip)
[PE viewer](https://download.cnet.com/PE-Viewer/3000-2352_4-10966763.html)

# 0x02 链接库与函数
对于一个可执行程序，可以收集到最有用的信息就是导入表。导入函数是程序所使用的但存储在另一程序中的那些函数。通过导入函数连接，使得不必重新在多个程序中重复实现特定功能。
1. 静态链接、运行时链接与动态链接。
静态链接：当一个库被静态链接到可执行程序时，所有这个库中的代码都会被复制到可执行程序中，这使得可执行程序增大许多，而且在分析代码时，很难区分静态链接的代码和自身代码。
运行时链接：在恶意代码中常用（加壳或混淆时），只有当需要使用函数时，才链接到库。
动态链接：当代码被动态链接时，宿主操作系统会在程序装载时搜索所需代码库，如果程序调用了被链接的库函数，这个函数会在代码库中执行。
LoadLibrary和GetProcAddress允许一个程序访问系统上任何库中的函数，因此当它们被使用时，无法静态分析出程序会链接哪些函数。
PE文件头存储了每个将被装载的库文件，以及每个会被程序使用的函数信息。
2. 工具Dependency Walker
[Dependency Walker](http://www.dependencywalker.com/)
3. 常见dll程序
***kernel32.dll***
kernel32.dll是Windows 9x/Me中非常重要的32位动态链接库文件，属于内核级文件。它控制着系统的内存管理、数据的输入输出操作和中断处理，当Windows启动时，kernel32.dll就驻留在内存中特定的写保护区域，使别的程序无法占用这个内存区域。
***user32.dll***
user32.dll是Windows用户界面相关应用程序接口，用于包括Windows处理，基本用户界面等特性，如创建窗口和发送消息。
在早期32-bit 版本的Windows中，用户控件是在ComCtl32中实现的，但是一些控件的显示功能是在User32.dll中实现的。例如在一个窗口中非客户区域（边框和菜单）的绘制就是由User32.dll来完成的。User32.dll 是操作系统的一个核心控件，它和操作系统是紧密联系在一起的。也就是说，不同版本的Windows中User32.dll 是不同。因此，应用程序在不同版本的Windows中运行的时候，由于User32.dll的不同，会导致应用程序的界面通常会有微小的不同。
***gdi32.dll***
gdi32.dll是Windows GDI图形用户界面相关程序，包含的函数用来绘制图像和显示文字
***comdlg32.dll***
comdlg32.dll是Windows应用程序公用对话框模块，用于例如打开文件对话框。
***advapi32.dll***
advapi32.dll是一个高级API应用程序接口服务库的一部分，包含的函数与对象的安全性，注册表的操控以及事件日志有关。
***shell32.dll***
shell32.dll是Windows的32位外壳动态链接库文件，用于打开网页和文件，建立文件时的默认文件名的设置等大量功能。
严格来讲，它只是代码的合集，真正执行这些功能的是操作系统的相关程序，dll文件只是根据设置调用这些程序的相关功能罢了。
***ole32.dll***
ole32.dll是对象链接和嵌入相关模块。
***odbc32.dll***
odbc32.dll是ODBC数据库查询相关文件。

2. 导入函数与导出函数
导入函数和导出函数都是用来和其他程序和代码进行交互时使用的，通常一个DLL会实现一个或多个功能函数，然后将他们导出，使得别的程序可以导入并使用这些函数，导出函数在DLL文件中是最常见的。

# 0x03 PE文件的结构
|PE文件结构|
|---------|
|MZ文件头|
|DOS插桩程序|
|字串“PE\0\0”(4字节)|
|映像文件头|
|可选映像头|
|Section table(节表)|
|Section 1|
|Section 2|
|.....|
1. DOS程序头(4H字节)
包括MZ文件头和DOS插桩程序。MZ文件头开始两个字节为4D5A。
2. NT映像头(14H字节)
存放PE整个文件信息分布的重要字段。包括：
- 签名（signature）：值为'50450000h'，字串为'PE\0\0'，可以在DOS程序头的3CH处的四个字节找到该字串的偏移位置
- 映像文件头（FileHeader）：是映像头的主要部分，包含PE文件最基本的信息。结构体为：
```
typedef struct _IMAGE_FILE_HEADER {   
        WORD      Machine;                 //运行平台
        WORD      NumberOfSections;        //节(section)数目      
        DWORD     TimeDateStamp;           //时间日期标记     
        DWORD     PointerToSymbolTable;    //COFF符号指针，这是程序调试信息    
        DWORD     NumberOfSymbols;         //符号数  
        WORD      SizeOfOptionalHeader;    //可选部首长度，是IMAGE_OPTIONAL_HEADER的长度    
        WORD      Characteristics;         //文件属性
}
```
3. 可选映像头(OptionalHeader)
包含PE文件的逻辑分布信息，共有13个域。具体结构为：
```
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;                               //代表的是文件的格式
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;                 //保存着EP的RVA。也就是最先执行代码起始地址。
  DWORD                BaseOfCode;                          //表示代码段起始RVA先看他的值，是1000
  DWORD                BaseOfData;
  DWORD                ImageBase;                           //默认装入基地址
  DWORD                SectionAlignment;                    //节区在内存中的最下单位
  DWORD                FileAlignment;                       //节区在磁盘中的最小单位
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;                         //装入内存后的总尺寸
  DWORD                SizeOfHeaders;                       //头尺寸=NT映像头+节表
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;
```
4. 节表
实际上是一个结构数组，其中每个结构包含了一个节的具体信息（每个结构占用28H字节）
```
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;                          //该节的实际字节数
  } Misc;
  DWORD VirtualAddress;                         //本节的相对虚拟地址
  DWORD SizeOfRawData;                          //对齐后的节尺寸
  DWORD PointerToRawData;                       //本节在文件中的地址
  DWORD PointerToRelocations;                   //本节调入内存后的存放位置
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;                        //节的属性
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```
5. 节
- 引入函数节(.rdata/.idata)
```
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real datetime stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
```
- 一个exe程序加载dll的IMAGE_IMPORT_DESCRIPTOR
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1556519313/pwn/1506049226526485.jpg)
