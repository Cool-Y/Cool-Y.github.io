---
title: Caving_db_storage
date: 2019-04-15 15:38:47
tags:
- 数据库
- 复原文件
- 取证
categories:
顶会论文
---

# Carving database storage to detect and trace security breaches
> 复原数据库存储以检测和跟踪安全漏洞
> [原文下载](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555312497/paper/2016-paper_carving_database_storage_to_detect_and.pdf)

## Motivation
### DBMS(数据库管理系统)
- 通常用于存储和处理敏感数据，因此，投入了大量精力使用访问控制策略来保护DBMS。
- 一旦用户在DBMS中获得提升权限（无论是合理的还是通过攻击的），实施的安全方案可以绕过，因此无法再根据政策保证数据受到保护。
1）访问控制策略可能不完整，允许用户执行他们不能执行的命令
2）用户可能通过使用DB或OS代码中的安全漏洞或通过其他方式非法获取权限
- 部署预防措施
1）在及时发生安全漏洞时检测安全漏洞;
2）在检测到攻击时收集有关攻击的证据，以便设计对抗措施并评估损害程度

### 例子
Malice是政府机构的数据库管理员，为公民提供犯罪记录。 Malice最近被判犯有欺诈罪，并决定滥用她的特权，并通过运行DELETE FROM Record WHERE name = 'Malice'来删除她的犯罪记录。
但是，她知道数据库操作需要定期审核，以检测对机构存储的高度敏感数据的篡改。为了覆盖她的操作，Malice在运行DELETE操作之前停用审计日志，然后再次激活日志。因此，在数据库中没有她的非法操纵的日志跟踪。
但是，磁盘上的数据库存储仍将包含已删除行的证据。
作者的方法检测已删除的痕迹和过期的记录版本，并将它们与审核日志进行匹配，以检测此类攻击，并提供数据库操作方式的证据。
作者将检测已删除的行，因为它与审计日志中的任何操作都不对应，我们会将其标记为篡改的潜在证据。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555310640/paper/%E5%9B%BE%E7%89%871.png)

### 思路一览
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555310736/paper/%E6%8D%95%E8%8E%B7.png)

### 提出方法
使用称为DICE的现有取证工具（Wagner等，2017）来重建数据库存储
通过匹配提取的存储条目，报告任何无法通过操作记录解释的工件来自动检测潜在的攻击
1. DBDetective检查数据库存储和RAM快照，并将它找到的内容与审计日志进行比较
2. 然后，在不影响数据库操作的情况下，对核心数据进行分析。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555310863/paper/%E5%9B%BE%E7%89%872.png)

确定数据库篡改的可能性，并指出数据库存储中发现的具体不一致性。
由于数据库存储的易变性，无法保证将发现所有攻击。
在对于我们评估的每个主要DBMS，我们假设DBMS已启用审计日志来捕获与调查相关的SQL命令。
我们进一步假设一名攻击者通过以下方式阻止记录已执行的恶意命令：
- 停用审计策略并暂时挂起日志记录
- 更改现有审计日志（两者都在数据库日志可靠性部分中讨论）。
通过将取证分析技术应用于数据库存储或缓冲区缓存，并将发现的证据与审计日志相匹配，可以：
- 检测DBMS审核日志中未显示的多种类型的数据库访问和操作。
- 将未归因的记录修改分类为模糊的INSERT，DELETE或UPDATE命令。
- 检测无法从审核日志中的活动派生的（只读）SELECT查询中的缓存数据。

## Reliability of database logs
攻击者可以更改两种类型的日志： write-ahead logs (WAL) and audit logs (event history records)
- WALs以低级别记录数据库修改以支持ACID保证，提供最近表修改的历史记录。
通常无法禁用或轻松修改WAL，并且需要读取专用工具（例如，Oracle LogMiner或PostgreSQL pg_xlogdump）。
某些DBMS允许为特定操作禁用WAL，例如批量加载或结构重建。因此，可以通过此功能插入记录而不留下日志跟踪。
- audit logs记录配置的用户数据库操作。包括SQL操作和其他用户活动。审计日志根据数据库管理员配置的日志记录策略存储已执行的SQL命令。 因此，管理员可以根据需要禁用日志记录或修改单个日志记录。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555311090/paper/%E5%9B%BE%E7%89%873.png)

## Detecting hidden record modifications
插入或修改表记录时，数据库中会发生一连串的存储更改。 除了受影响记录的数据本身之外，页面元数据会更新（例如，设置删除标记），并且存储记录的索引的页面会改变（例如，以反映记录的删除）。 如果尚未缓存，则每个访问的页面都将被带入RAM。 行标识符和结构标识符可用于将所有这些更改绑定在一起。
此外，DBA（数据库管理员）还可以禁用批量修改的日志记录（出于性能考虑）——可以利用此权限来隐藏恶意修改。
在本节中，我们将描述如何检测已修改记录与已记录命令之间的不一致。
### Deleted records
1. 算法
删除的记录不会被物理删除，而是在页面中标记为“已删除”; 已删除行占用的存储空间将成为未分配的空间，最终将被新行覆盖。这些对数据库存储的更改不能被绕过或控制。
识别存储中与日志中的任何删除操作都不匹配的已删除行。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555311166/paper/%E5%9B%BE%E7%89%874.png)
2. 实例
- DICE从Customer表重建了三个删除的行
（1，Christine，Chicago）
（3，Christopher，Seattle）
（4，Thomas，Austin）
- 日志文件包含两个操作
在算法1中，DeletedRows被设置为三个重建的已删除行。
算法1返回（4，Thomas，Austin），表示该删除的记录不能归因于任何删除。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555311315/paper/%E5%9B%BE%E7%89%875.png)

### Inserted records
1. 算法
新插入的行将附加到表的最后一页的末尾（如果最后一页已满，则为新页）或覆盖由先前删除的行创建的可用空间。
如果“活跃”新表行与审核日志中的任何插入操作都不匹配，则此行是可疑活动的标志。
算法2中使用这些“活跃”记录来确定重构行是否可归因于审计日志中的插入。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555311991/paper/%E5%9B%BE%E7%89%876.png)
2. 实例
- 该日志包含六个操作。
当行从T1插入到T4时，它们将附加到表的末尾。
在T5，删除（3，Lamp）
然后在T6插入（5，Bookcase）。
由于row（5，Bookcase）大于删除的行（3，Lamp），因此它将附加到表的末尾。
- DICE重建了五个活动记录
包括（0，Dog）和（2，Monkey）
行被初始化为算法2的五个重建活动行
算法2因此返回（0，Dog）和（2，Monkey）
因为这些记录无法与记录的插入匹配。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555312072/paper/%E5%9B%BE%E7%89%877.png)

### Updated records
1. 算法
UPDATE操作本质上是一个DELETE操作，后跟一个INSERT操作。
为了考虑更新的行，我们使用算法1返回的未标记删除行和算法2返回的未标记插入行作为算法3的输入。如果删除的行可以与更新的WHERE子句匹配，那么此删除的行操作 被标记为存在于日志中。 接下来，如果未标记的插入行可以与SET子句中的值匹配，并且插入的行匹配已删除行中除SET子句值之外的所有值，则此插入的行操作将出现在日志中。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555312183/paper/%E5%9B%BE%E7%89%878.png)
2. 实例
算法1返回行（2，Desk）
算法2返回行（0，Dog）和（2，Monkey）
使用这些记录集，算法3返回（2，Desk）作为已删除记录的列表，并将（0，Dog）和（2，Monkey）作为插入记录的列表。
此外，算法3识别（2，Desk）和（2，Monkey）中第一列的共享值2。 虽然这不能单独确认UPDATE操作，但可以合理地得出结论：
（2，Desk）已更新为（2，Monkey）。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555312234/paper/%E5%9B%BE%E7%89%879.png)

## Detecting inconsistencies for read-only queries
DBMS使用称为缓冲区管理器的组件将页面从磁盘缓存到内存中。数据以页为单位读入缓冲池，可以通过DICE重建。
在本节中，将描述如何将缓冲池中的工件与审计日志中的只读查询进行匹配。
数据库查询可以使用两种可能的访问表的方式之一：
全表扫描（FTS）或索引扫描（IS）。
FTS读取所有表页，而IS使用索引结构来检索引用基于搜索关键字的指针列表。
### Full table scan
当查询使用FTS时，只会缓存大表的一小部分。 可以完整地缓存小表（相对于缓冲池大小）。 每个数据库都在页眉中存储唯一的页面标识符，这使我们能够有效地将缓存的页面与磁盘上的对应页面进行匹配。
我们可以通过SID=131识别属于Employee的页面，该SID=131存储在页面标题中。 DICE只能以更快的速度返回页面结构标识符（无需解析页面内容）。
Q2和Q4都通过FTS访问员工。 每次扫描Employee表时，表中相同的四个页面（PID：97,98,99和100）都会加载到缓冲池中。
因此，当在存储器中找到具有PID:97,98,99和100以及SID:131的四个页面时，可以假设FTS应用在Employee表上。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555312316/paper/%E5%9B%BE%E7%89%8710.png)

### Index access
Customer表的SID=124，C_City列上的二级索引的SID=126.
Q1在城市Dallas上进行过滤，并使用PID=2缓存索引页。此页面的最小值为Chicago和最大值为Detroit 。
Q3在城市Jackson上过滤，并缓存索引页面，页面标识符为4.此页面的最小值为Houston，最大值为Lincoln。
如果审核日志中的查询过滤了索引页的最小值和最大值范围内的值，则该页可以归因于该查询。
![](https://res.cloudinary.com/dozyfkbg3/image/upload/v1555312359/paper/%E5%9B%BE%E7%89%8711.png)


### Conclusions and future work
- 审计日志和其他内置DBMS安全机制旨在检测或阻止攻击者执行的恶意操作。这种机制的固有缺点是具有足够权限的攻击者可以绕过它们来隐藏它们的踪迹。
- 我们提供并全面评估DBDetective，它可以检测攻击者通过从审计日志中删除从而隐藏的数据库操作，并收集有关攻击者访问和修改哪些数据的证据。
- 我们的方法依赖于对数据库存储的取证检查，并将此信息与审核日志中的条目相关联，以发现恶意操作的证据。
- 重要的是，数据库存储几乎不可能被欺骗，因此，与例如审计日志相比，它是更可靠的篡改证据来源。
- 鉴于存储快照提供的信息不完整，我们将探索概率匹配，确定存储工件由审计日志中的操作引起的可能性，根据操作的时间顺序利用其他约束，模拟审计中SQL命令的部分历史记录获得更精确的匹配，并根据检测到的异常动态调整拍摄快照的频率。
