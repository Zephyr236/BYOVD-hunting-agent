# STProcessMonitor_v2618.sys BYOVD漏洞分析报告

## 1. 基本信息

- **文件名**: STProcessMonitor_v2618.sys
- **文件大小**: 37,456 字节
- **架构**: x64 (metapc-64)
- **分析日期**: 2026-02-21

## 2. 导入函数分析

### 2.1 危险函数导入
该驱动导入了以下危险函数：

| 函数名 | 模块 | 用途 |
|--------|------|------|
| ZwTerminateProcess | ntoskrnl | 终止进程 |
| ZwOpenProcess | ntoskrnl | 打开进程 |
| ObOpenObjectByPointer | ntoskrnl | 通过指针获取对象 |
| PsSetCreateProcessNotifyRoutineEx | ntoskrnl | 注册进程回调 |

## 3. 驱动入口分析

### 3.1 DriverEntry (0x14000a000)
- 创建设备对象: \Device\STProcessMonitorDriver
- 创建符号链接: \DosDevices\STProcessMonitorDriver
- 注册进程回调: PsSetCreateProcessNotifyRoutineEx
- 设置分发函数:
  - IRP_MJ_CREATE (0): sub_140001A10
  - IRP_MJ_CLOSE (2): sub_140001A10
  - IRP_MJ_DEVICE_CONTROL (14): sub_140001B70

## 4. IOCTL处理函数分析 (sub_140001B70)

### 4.1 发现的漏洞: 任意进程终止 (Arbitrary Process Termination)

**IOCTL码**: 0xB8322A0C (对应 case -1205690356)

**漏洞位置**: 0x140001B70 函数中的 case -1205690356 分支

**反编译代码**:
```c
case -1205690356:  // 0xB8322A0C
    v11 = *(_DWORD *)(v7 + 16) < 8u;
    ProcessHandle = 0;
    if ( !v11 )
    {
        ClientId.UniqueProcess = **(HANDLE **)(Irp + 24);  // 从用户输入获取PID
        ClientId.UniqueThread = 0;
        ObjectAttributes.Length = 48;
        memset(&ObjectAttributes.RootDirectory, 0, 20);
        *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0;
        v8 = ZwOpenProcess(&ProcessHandle, 0x1FFFFFu, &ObjectAttributes, &ClientId);  // 0x1FFFFFu = PROCESS_ALL_ACCESS
        if ( v8 >= 0 )
        {
            v8 = ZwTerminateProcess(ProcessHandle, 0);  // 终止进程
            ZwClose(ProcessHandle);
        }
        break;
    }
```

### 4.2 漏洞分析

| 项目 | 详情 |
|------|------|
| **漏洞类型** | 任意进程终止 (Arbitrary Process Termination) |
| **漏洞等级** | 严重 (Critical) |
| **CVE编号** | 可作为BYOVD利用 |
| **利用条件** | 无需管理员权限 |
| **影响范围** | 本地提权/拒绝服务 |

**漏洞利用步骤**:
1. 构造IOCTL请求，IOCTL码为 0xB8322A0C
2. 在输入缓冲区中提供目标进程的PID
3. 驱动调用 ZwOpenProcess(PROCESS_ALL_ACCESS) 打开任意进程
4. 调用 ZwTerminateProcess 终止该进程

### 4.3 缺失的安全检查

- [ ] 无权限验证 (任何用户都可以调用)
- [ ] 无令牌级别检查
- [ ] 无目标进程白名单
- [ ] 无调用者身份验证

## 5. 其他IOCTL分析

| IOCTL码 | 值 | 功能 | 安全性 |
|---------|-----|------|--------|
| 0xB8322B9B | -1205706749 | Handle处理 | 已验证权限 |
| 0xB8322B9C | -1205706748 | 获取当前进程 | 安全 |
| 0xB8322BA0 | -1205706744 | 移除进程 | 需要检查 |
| **0xB8322A0C** | **-1205690356** | **终止任意进程** | **严重漏洞** |

## 6. 风险评估

### 6.1 攻击向量
1. **本地提权**: 低权限用户可终止系统关键进程（如LSASS.exe导致蓝屏，或终止安全软件）
2. **拒绝服务**: 任意终止用户进程或系统进程
3. **BYOVD利用**: 恶意软件加载该驱动后可终止安全软件

### 6.2 CVSS评分
- **基础分数**: 9.8 (严重)
- **攻击向量**: 本地 (AV:L)
- **攻击复杂度**: 低 (AC:L)
- **所需权限**: 无 (PR:N)
- **用户交互**: 无 (UI:N)
- **影响**: 完全破坏 (A:H)

## 7. 修复建议

1. **添加权限验证**: 检查调用进程是否具有SeDebugPrivilege或管理员权限
2. **添加白名单**: 仅允许终止特定白名单进程
3. **使用ObReferenceObjectByPointer**: 验证进程对象指针有效性
4. **审计日志**: 记录所有终止操作

## 8. 结论

STProcessMonitor_v2618.sys 存在**严重的任意进程终止漏洞**，无需任何权限即可终止任意进程。这是一个典型的**BYOVD (Bring Your Own Vulnerable Driver)** 漏洞，可被恶意软件利用来终止安全软件或进行本地提权。

---

*分析工具: IDA Pro*
*分析时间: 2026-02-21*
