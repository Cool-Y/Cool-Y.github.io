---
title: Dolphin Attack 论文复现
date: 2021-01-08 12:54:41
tags:
- 硬件攻击
- 传感器
- 语音助手
categories:
- 顶会论文
---

# 海豚音攻击-复现
文章中提到两种方案，一是具有信号发生器的强大变送器，二是带有智能手机的便携式变送器；前一种方案成本过于高，本文不做分析，后一种方案的实现成本在我们可接收的范围。
但原文中对后一方案的实现没有太多介绍，于是我通过邮件咨询了作者-闫琛博士，闫博士非常友好，我是在晚上十点发送的第一封邮件，差不多在十分钟内通过几封邮件的交流，解决了我的问题，很快确定了我的具体实现路径，非常感谢大佬！
* Q: 使用便携式设备攻击的时候，三星Galaxy S6 Edge发送的高频声音信号是怎么生成的呢？是预先使用专业设备调制好的信号保存为mp3吗？
* A: 通过软件调制，生成.wav的超声波音频文件，再通过三星手机播放的。
* Q: 用的是什么软件进行调制?
* A: 用过matlab和python，都是可以的

## 0x01 语音命令生成

https://ttstool.com/
微软的TTS接口生成的是mp3格式音频，一般来说我们使用python处理音频都是针对wav格式。
https://www.aconvert.com/cn/audio/mp3-to-wav/
我们可以通过这个网站对格式做转换。
[xiaoyi.wav](https://coolyim.quip.com/-/blob/OVVAAAmjZcr/Eq9qXdQ7_eD5KQaR33wCCw?name=xiaoyi.wav)
这个网站的采样率最高只能达到96000hz
[6wxmu-crusr.wav](https://coolyim.quip.com/-/blob/OVVAAAmjZcr/aZfltfEV_ZxV1LCGznB1OA?name=6wxmu-crusr.wav)

## 0x02 语音命令调制

生成语音命令的基带信号后，我们需要在超声载波上对其进行调制，以使它们听不到。 为了利用麦克风的非线性，DolphinAttack必须利用幅度调制（AM）。
### AM调制原理
使载波的振幅按照所需传送信号的变化规律而变化，但频率保持不变的调制方法。调幅在有线电或无线电通信和广播中应用甚广。调幅是高频载波的振幅随信号改变的调制（AM）。其中，载波信号的振幅随着调制信号的某种特征的变换而变化。例如，0或1分别对应于无载波或有载波输出，电视的图像信号使用调幅。调频的抗干扰能力强，失真小，但服务半径小。
假设载波uc(t)和调制信号的频率分别为ωc和Ω，在已调波中包含三个频率成分：ωc、ωc+Ω和ωc-Ω。ωc+Ω称为上边频，ωc-Ω称为下边频。

https://epxx.co/artigos/ammodulation.html
http://www.chenjianqu.com/show-44.html
https://zhuanlan.zhihu.com/p/54561504
http://www.mwhitelab.com/archives/208


### 使用python调制

现在我们已经有了基带信号，使用[Audacity](https://www.fosshub.com/Audacity.html)对其进行频谱分析，此语音的带宽或频谱（左图为采样频率48khz音频，右图为96khz） ：
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610082052/Dolphin%20Attack/08_YW7UW_PS_TOE_LZZY.png)
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610082052/Dolphin%20Attack/WGD_U453KYP3M3_2639_5I.png)

我们可以看到带宽为8000-9000hz左右，这是女声，因此频带范围较宽。这可能导致可听范围内的频率泄露，但这里我们先不去讨论，之后再使用带宽较小的语音以创建基带语音信号。
wave包最多能读取的wav音频采样率为[48khz](https://github.com/jiaaro/pydub/issues/134)，当超过这个值时，wave就不再支持（wave.Error: unknown format: 65534）。但我们的载波频率为30khz左右，这就要求音频文件的采样率高于60khz才能保证不失真。所幸[`scipy.io.wavfile`](https://kite.com/python/docs/scipy.io.wavfile)支持高于48khz的wav文件读取。
使用以下Python程序来生成调制的AM和AM-SC音频，AM是广播无线电调制的“正常”声音，它加上了载波；AM-SC则只是载波与原始信号的乘积。


```python
# coding=utf-8
import numpy as np
import matplotlib.pyplot as plt
import os
import wave
import struct
import math
from pydub import AudioSegment
import scipy.io.wavfile

def main():
    test = scipy.io.wavfile.read("xiaoyi.wav")
    nframes = len(test[1])
    waveData = np.fromstring(test[1],dtype=np.short)#将原始字符数据转换为整数
    #音频数据归一化
    maxW = max(abs(waveData))
    waveData = waveData * 1.0/maxW
    #将音频信号规整乘每行一路通道信号的格式，即该矩阵一行为一个通道的采样点，共nchannels行
    Tdata = np.reshape(waveData,[nframes,1]).T # .T 表示转置
    am = wave.open("am.wav", "w")
    amsc = wave.open("amsc.wav", "w")
    carrier = wave.open("carrier3000.wav", "w")
    for f in [am,amsc,carrier]:
        f.setnchannels(1)
        f.setsampwidth(2)
        f.setframerate(96000)
    for n in range(0, nframes):
        carrier_sample = math.cos(30000.0 * (n / 96000.0) * math.pi * 2)
        signal_am = signal_amsc= waveData[n] * carrier_sample
        signal_am += carrier_sample
        signal_am /= 2
        am.writeframes(struct.pack('h', signal_am * maxW))
        amsc.writeframes(struct.pack('h', signal_amsc * maxW))
        carrier.writeframes(struct.pack('h', carrier_sample * maxW))


if __name__=='__main__':
    main()
```


分别对am.wav、amsc.wav、carrier3000.wav做频谱分析
carrier3000.wav的频谱的为集中在载波频率30khz上的一个脉冲[carrier3000.wav](https://coolyim.quip.com/-/blob/OVVAAAmjZcr/9RE4Z0lCs1WACO75zLTAhA?name=carrier3000.wav)
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610082051/Dolphin%20Attack/K5447O57_S___A_O_Q3V.png)
amsc.wav的带宽约为18khz，是原来的两倍，关于f=30khz镜面对称。AM调制会创建原始信号的两个“副本”，一个在21-30kHz频段，另一个在30-39kHz。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610082052/Dolphin%20Attack/OPSXK_21_7R24_I_NIWM0_8.png)

am.wav，在这种调制中，我们可以听到载波，而在AM-SC中则听不到。频谱类似于AM-SC，但在载波频率上还有一个尖锐的“尖峰”：
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610082051/Dolphin%20Attack/G8_K4_ZG__PE2CQ_5_UYY.png)


## 0x03 语音命令发送器
下图是由智能手机驱动的便携式发射器。便携式发射器利用智能手机来发射调制信号。许多设备的最佳载波频率都大于24 kHz， 大多数智能手机无法完成任务。大多数智能手机最多支持48 kHz采样率，所以只能发送载波频率最高为24 kHz的调制窄带信号。需要支持高达192 kHz的采样率的手机，而且扬声器会衰减频率大于20 kHz的信号。为了减轻这个问题，我使用窄带超声换能器作为扬声器，并在超声换能器之前添加了一个放大器，这样有效的攻击范围得以扩展。

![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1610082508/Dolphin%20Attack/Snipaste_2021-01-08_13-06-55.png)
