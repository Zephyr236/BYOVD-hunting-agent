# STProcessMonitor_v114.sys BYOVD漏洞分析报告

## 1. 漏洞概述

| 项目 | 详情 |
|------|------|
| **文件** | STProcessMonitor_v114.sys |
| **厂商** | ST (Security Tools) |
| **架构** | x64 (metapc-64) |
| **漏洞类型** | 任意进程终止 (Arbitrary Process Termination) |
| **风险等级** | 严重 (Critical) |

## 2. 危险API导入

该驱动导入了以下危险函数，可被用于BYOVD攻击：

| API | 用途 |
|-----|------|
| `ZwTerminateProcess` | 终止任意进程 |
| `ZwOpenProcess` | 打开任意进程句柄 |

## 3. 漏洞详情

### 3.1 IOCTL处理函数

- **函数地址**: `sub_140001B70`
- **IRP Major Function**: IRP_MJ_DEVICE_CONTROL (0x0E)

### 3.2 漏洞IOCTL码

| IOCTL码 | 功能 | 漏洞 |
|---------|------|------|
| 0xB8222004 | 事件处理 | 无 |
| 0xB8222008 | 清除操作 | 无 |
| 0xB822200C | 获取数据 | 无 |
| **0xB8222010** | **进程终止** | **任意PID终止** |

### 3.3 漏洞代码分析

```c
// IOCTL 0xB8222010 处理代码
case 0xB8222010:
    // 检查输入缓冲大小 >= 8字节
    if (*(_DWORD *)(v7 + 16) < 8u)
    {
        v8 = -1073741789;  // STATUS_INFO_LENGTH_MISMATCH
        break;
    }
    
    // 从用户态获取进程PID
    ClientId.UniqueProcess = **(HANDLE **)(Irp + 24);
    ClientId.UniqueThread = 0;
    
    // 构造对象属性
    ObjectAttributes.Length = 48;
    memset(&ObjectAttributes.RootDirectory, 0, 20);
    
    // 关键漏洞：无权限校验，使用最高权限 0x1FFFFF
    v8 = ZwOpenProcess(&ProcessHandle, 0x1FFFFFu, &ObjectAttributes, &ClientId);
    
    if (v8 >= 0)
    {
        // 直接终止进程
        v8 = ZwTerminateProcess(ProcessHandle, 0);
        ZwClose(ProcessHandle);
    }
    break;
```

### 3.4 漏洞利用条件

1. **无权限校验**: 驱动没有验证调用者权限，任何用户态程序都可调用
2. **无调用者检查**: 没有检查是否是合法请求
3. **最高权限**: 使用 `DesiredAccess = 0x1FFFFF` (PROCESS_ALL_ACCESS)
4. **直接终止**: 直接调用 `ZwTerminateProcess` 无任何保护

## 4. BYOVD攻击场景

### 攻击流程

1. 攻击者获取目标系统权限
2. 加载存在漏洞的 `STProcessMonitor_v114.sys` 驱动
3. 通过IOCTL 0xB8222010发送任意进程PID
4. 驱动使用内核权限终止目标进程（如杀软、安全产品）

### 攻击示例

```
IOCTL: 0xB8222010
Input: [Target PID] (8 bytes)
Output: NTSTATUS
```

## 5. 修复建议

1. **添加权限校验**: 验证调用者是否有权限终止目标进程
2. **白名单机制**: 只允许终止特定进程或来自特定进程的请求
3. **最小权限原则**: 使用最小必要权限而非 `0x1FFFFF`
4. **调用者验证**: 检查调用进程是否受信任

## 6. 结论

**该驱动存在严重的BYOVD漏洞**，允许任意用户态程序以内核权限终止系统任意进程。攻击者可利用此漏洞禁用杀毒软件和安全产品，进行恶意软件部署。

---
*分析时间: 2024*
*分析工具: IDA Pro*
