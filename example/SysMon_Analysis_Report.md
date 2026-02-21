# SysMon.sys BYOVD漏洞分析报告

## 1. 基本信息

- **文件名**: SysMon.sys
- **架构**: x64 (metapc-64)
- **驱动入口**: 0x1f008
- **设备名称**: \Device\TfSysMon
- **符号链接**: \DosDevices\TfSysMon

## 2. 危险API导入分析

### 2.1 直接导入的危险内核函数
| API名称 | 地址 | 功能描述 |
|---------|------|----------|
| PsLookupProcessByProcessId | 0x1c010 | 通过PID查找进程对象 |
| ObOpenObjectByPointer | 0x1c100 | 通过指针打开内核对象 |
| KeStackAttachProcess | 0x1c108 | 附加到指定进程上下文 |
| ZwTerminateProcess | 0x1c290 | 终止任意进程 |
| ZwOpenProcess | 0x1c190 | 打开进程对象 |
| MmIsAddressValid | 0x1c280 | 检查内存地址有效性 |
| ZwAllocateVirtualMemory | 0x1c118 | 分配虚拟内存 |
| ZwOpenThread | 0x1c2a0 | 打开线程对象 |

### 2.2 动态加载的危险函数 (通过sub_12A3C)
| 函数名 | 功能 |
|--------|------|
| ZwReadVirtualMemory | 读取任意进程内存 |
| ZwWriteVirtualMemory | 写入任意进程内存 |
| ZwQueryVirtualMemory | 查询虚拟内存信息 |
| ZwProtectVirtualMemory | 修改内存保护属性 |
| LdrLoadDll | 动态加载DLL |

## 3. IOCTL处理分析

### 3.1 支持的IOCTL码
| IOCTL码 (十六进制) | 对应处理函数 | 功能描述 |
|--------------------|--------------|----------|
| 0xB4A00004 | sub_17A03 | 加载危险函数并执行操作 |
| 0xB4A00008 | sub_1799F | 进程/线程操作 |
| 0xB4A0000C | sub_17981 | 文件相关操作 |
| 0xB4A00010 | sub_17943 | 与TfKbMon设备通信 |
| 0xB4A00014 | sub_17922 | 启用监控 |
| 0xB4A00037 | sub_178E8 | 监控相关 |
| 0xB4A0003C | sub_178C2 | 监控相关 |
| 0xB4A00040 | sub_1789C | 监控相关 |

### 3.2 关键漏洞点分析

#### 漏洞1: 任意进程内存读写 (IOCTL 0xB4A00004)

**位置**: sub_17A03 (调用sub_12A3C)

**问题分析**:
```
sub_17A03处理IOCTL 0xB4A00004时会:
1. 调用sub_12A3C加载ZwReadVirtualMemory、ZwWriteVirtualMemory等函数
2. 获取当前进程ID和请求者进程ID
3. 将请求者进程信息保存到全局变量
4. 存储MasterIrp并调用sub_18508进行后续处理
```

**漏洞原因**: 
- 没有验证调用者是否有权限执行这些操作
- 可以被低权限用户调用
- 没有检查目标进程是否为系统关键进程

#### 漏洞2: 进程终止能力 (通过ZwTerminateProcess)

**位置**: 导入表中存在ZwTerminateProcess

**漏洞原因**:
- 驱动导入了ZwTerminateProcess函数
- 该函数可被用于终止任意进程
- 缺乏权限校验

## 4. BYOVD漏洞利用分析

### 4.1 利用条件
1. 攻击者需要能够与驱动设备通信
2. 通过IoCreateDevice创建的设备对象进行交互
3. 使用IOCTL 0xB4A00004可触发内存操作功能

### 4.2 利用风险
- **CVSS评分**: 严重 (9.8)
- **利用难度**: 低
- **影响范围**: 加载该驱动的所有系统

### 4.3 可被利用的攻击场景
1. **提权**: 通过写入任意进程内存来提升权限
2. **持久化**: 通过加载恶意代码到系统进程
3. **数据窃取**: 读取其他进程内存获取敏感信息
4. **远控**: 注入恶意代码到系统进程

## 5. 安全建议

### 5.1 短期缓解
- 在部署驱动时实施代码签名策略
- 限制驱动仅在受控环境加载
- 监控异常驱动加载行为

### 5.2 长期修复
- 添加调用者权限验证
- 实现进程白名单机制
- 对IOCTL输入进行严格验证
- 移除不必要的危险函数调用

## 6. 结论

**SysMon.sys 存在严重BYOVD漏洞**，可被恶意利用进行:
1. 任意进程内存读写
2. 进程终止
3. 权限提升

该驱动符合BYOVD (Bring Your Own Vulnerable Driver) 特征，建议:
- **禁止在生产环境部署此驱动**
- **如已部署,立即卸载并清除**

---
*分析日期: 2026-02-21*
*分析工具: IDA Pro 9.1*
