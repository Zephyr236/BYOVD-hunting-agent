# K7RKScan_1516.sys BYOVD漏洞分析报告

## 1. 基本信息

| 项目 | 值 |
|------|-----|
| 文件名 | K7RKScan_1516.sys |
| 文件路径 | C:\Users\user\Desktop\BYOVD\K7RKScan_1516.sys |
| 架构 | x64 |
| 驱动入口点 | 0x17008 |
| IOCTL分发函数 | 0x114A0 (sub_114A0) |

## 2. 危险API导入分析

该驱动导入了以下危险API，可能被用于恶意目的：

| API | 用途 | 风险等级 |
|-----|------|----------|
| ZwTerminateProcess | 终止进程 | **严重** |
| PsLookupProcessByProcessId | 根据PID获取进程对象 | **严重** |
| ObOpenObjectByPointer | 打开进程对象 | **严重** |
| PsInitialSystemProcess | 获取系统进程 | 中 |
| MmIsAddressValid | 内存地址有效性检查 | 低 |

## 3. 发现的严重漏洞

### 3.1 任意进程终止漏洞 (CVE-2025-????)

**漏洞位置**: IOCTL 0x1FFFFF4 处理分支 (地址 0x11587)

**漏洞描述**:
该驱动程序提供了一个IOCTL接口，允许用户模式下程序直接终止任意进程，且**没有任何权限校验**。

**漏洞利用条件**:
- 攻击者只需能够与该驱动设备进行通信
- 无需任何特殊权限
- 攻击者只需知道目标进程的PID

**漏洞代码分析**:
```assembly
; 从用户输入获取ProcessId
mov     eax, [rax]        ; ProcessId = [rdx+18h]
call    PsLookupProcessByProcessId  ; 获取进程对象
call    ObOpenObjectByPointer        ; 打开进程对象
call    ZwTerminateProcess           ; 直接终止进程！
```

**利用方法**:
```c
// 构造IOCTL请求
IOCTL = 0x1FFFFF4;
// 在输入缓冲区提供目标进程PID
// 调用DeviceIoControl即可终止任意进程
```

### 3.2 进程对象操作漏洞

**漏洞位置**: IOCTL 0x1FFFFF4 和 0x222008 处理

**漏洞描述**:
驱动程序使用用户提供的ProcessId直接调用`PsLookupProcessByProcessId`，没有验证：
- ProcessId的有效性
- 调用者是否有权限操作该进程
- 目标进程是否存在

### 3.3 注册表操作漏洞

**漏洞位置**: IOCTL 0x222000 处理分支 (地址 0x117A0)

**漏洞描述**:
该驱动使用动态获取的Zw系列函数（ZwOpenKey, ZwQueryKey等）进行注册表操作，可能被利用进行：
- 注册表键枚举
- 注册表键值查询/修改
- 注册表键删除

## 4. IOCTL码分析

| IOCTL码 | 处理地址 | 功能 | 风险 |
|---------|----------|------|------|
| 0x222020 | 0x119CE | 字符串操作 | 低 |
| 0x222008 | 0x1199B | 进程操作 | 中 |
| 0x222004 | 0x11948 | 内存操作 | 中 |
| 0x222000 | 0x117A0 | 注册表操作 | 中 |
| 0x1FFFFF8 | 0x1161A | 内存分配 | 低 |
| **0x1FFFFF4** | **0x11587** | **进程终止** | **严重** |

## 5. 保护机制分析

### 5.1 DriverEntry中的反调试

```c
// DriverEntry中的magic number检查
if (!BugCheckParameter2 || BugCheckParameter2 == 0x2B992DDFA232)
{
    BugCheckParameter2 = (address ^ 0xFFFFF78000000320) & 0xFFFFFFFFFFFF;
    if (!BugCheckParameter2)
        BugCheckParameter2 = 0x2B992DDFA232;
}
```

这个检查可能是用于：
- 检测调试器
- 驱动完整性验证
- 反分析保护

### 5.2 设备访问控制

设备名: `\Device\NTK7RKScnDrv`
符号链接: `\DosDevices\DosK7RKScnDrv`

默认情况下，任何特权用户都可以访问该设备。

## 6. BYOVD利用分析

### 6.1 利用场景

该驱动可以被恶意软件或攻击者利用作为"BYOVD"（Bring Your Own Vulnerable Driver）工具：

1. **持久化**
   - 攻击者可以安装该驱动作为持久化机制
   
2. **权限维持**
   - 即使系统清理了恶意软件，驱动仍可重新加载

3. **杀软绕过**
   - 使用合法签名的驱动可以绕过杀软的驱动签名强制执行(DSME)

### 6.2 实际威胁

- **可直接终止安全软件进程**（如防病毒软件）
- **可终止关键系统进程**导致蓝屏
- **可进行注册表操作**修改系统设置
- **可进行任意内存操作**

## 7. 漏洞风险评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 严重性 | **严重** | 可直接终止任意进程 |
| 可利用性 | **高** | 无需特殊权限即可触发 |
| 影响范围 | **广** | 所有使用该驱动的系统 |
| 漏洞利用难度 | **低** | 只需发送特定IOCTL |

## 8. 修复建议

1. **添加权限校验**
   - 检查调用者是否具有SeDebugPrivilege或相应权限
   - 验证目标进程是否属于调用者

2. **限制操作范围**
   - 只允许终止用户自己的进程
   - 添加白名单/黑名单机制

3. **输入验证**
   - 验证ProcessId的有效性
   - 防止整数溢出和空指针解引用

4. **驱动签名**
   - 撤销或更新驱动签名
   - 使用Microsoft PPBL（Protected Process Light）列表

## 9. 结论

**K7RKScan_1516.sys 存在严重的BYOVD漏洞**

该驱动提供了任意进程终止功能，没有任何权限校验，是一个典型的不安全驱动例子。该驱动如果被安装到系统中，可以被恶意软件利用来：
- 终止安全软件
- 终止系统关键进程导致BSOD
- 进行权限维持

**建议**: 立即从系统中移除该驱动，并检查系统是否已被利用。

---
*分析日期: 2026-02-21*
*分析工具: IDA Pro*
