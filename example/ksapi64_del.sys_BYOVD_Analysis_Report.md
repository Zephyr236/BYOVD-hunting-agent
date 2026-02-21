# ksapi64_del.sys BYOVD 漏洞分析报告

## 1. 基本信息

- **文件名**: ksapi64_del.sys
- **文件路径**: C:\Users\user\Desktop\BYOVD\ksapi64_del.sys
- **文件大小**: 89,776 字节
- **架构**: x64 (metapc-64)
- **分析日期**: 2026-02-21

## 2. 危险 API 导入分析

该驱动导入了以下危险的内核 API：

| API 函数 | 用途 | 危险等级 |
|---------|------|---------|
| ZwTerminateProcess | 终止任意进程 | HIGH |
| PsLookupProcessByProcessId | 通过 PID 查找进程对象 | HIGH |
| ObOpenObjectByPointer | 通过指针打开对象 | HIGH |
| KeStackAttachProcess | 附加到进程内核栈 | HIGH |
| ZwOpenProcess | 打开进程 | HIGH |
| MmIsAddressValid | 检查内存地址有效性 | MEDIUM |
| ZwQuerySystemInformation | 查询系统信息 | MEDIUM |

## 3. BYOVD 漏洞确认

### 3.1 Windows 版本检测 (sub_188B0)

驱动在 DriverEntry 中调用 `sub_188B0` 来检测 Windows 版本：

```c
switch (MajorVersion) {
    case 5:  // Windows XP
        n4 = 1-3;
        break;
    case 6:  // Windows Vista/7/8
        n4 = 4-8;
        break;
    case 10: // Windows 10
        switch (BuildNumber) {
            case 0x2800:  n4 = 9;  break;  // 10240
            case 0x295A:  n4 = 10; break;  // 10586
            case 0x3839:  n4 = 11; break;  // 14393
            case 0x3AD7:  n4 = 12; break;  // 15063
            case 0x3FABu: n4 = 13; break;  // 16299
        }
}
```

### 3.2 系统服务表扫描 (sub_11970)

**这是最关键的 BYOVD 证据！**

`sub_11970` 函数执行以下操作：
1. 使用 `MmGetSystemRoutineAddress` 获取 `KeAddSystemServiceTable` 地址
2. 在内核中搜索字节模式来定位系统服务表
3. 根据不同的 Windows 版本 (n4 = 4-13) 使用不同的偏移量

```c
// 根据版本选择不同的扫描逻辑
if (n4 != 4 && n4 != 5 && n4 != 6 && n4 != 7 && n4 != 8)
{
    if (n4 == 9 || n4 == 10) { /* Windows 10 早期版本 */ }
    else if (n4 == 11 || n4 == 12 || n4 == 13) { /* Windows 10 后期版本 */ }
}
else { /* Windows Vista/7/8 */ }
```

### 3.3 版本特定的函数扫描 (sub_120E0, sub_12220 等)

每个版本对应一个专门的扫描函数：
- `sub_120E0` (n4=4)
- `sub_11FF0` (n4=5)
- `sub_12120` (n4=6)
- `sub_12220` (n4=7-8)
- `sub_12320` (n4=9)
- `sub_12420` (n4=10)
- `sub_12520` (n4=11)
- `sub_12620` (n4=12)
- `sub_12720` (n4=13)

这些函数执行内核模式下的字节模式匹配，以找到特定 Windows 版本的内核函数地址。

## 4. IOCTL 漏洞分析

### 4.1 IOCTL 处理函数

驱动注册了多个 MajorFunction：
- IRP_MJ_CREATE (0)
- IRP_MJ_CLOSE (2)
- IRP_MJ_DEVICE_CONTROL (14) -> sub_12A30
- IRP_MJ_SYSTEM_CONTROL (18)

### 4.2 权限检查分析

在 `sub_12A30` 中存在管理员权限检查：

```asm
12a73  call    SeCaptureSubjectContext
12a87  call    SeTokenIsAdmin
12a8f  jz      short loc_12A95  ; 如果不是管理员则跳转
```

但是：
1. **仅检查管理员权限** - 没有检查是否是内核模式调用
2. **可能被绕过** - 在某些场景下可以通过 SeDebugPrivilege 提升权限

### 4.3 任意进程终止漏洞 (IOCTL 0x222440)

在 `sub_19FD0` 中：

```c
// 从 IRP 中读取 PID
n4_1 = *(_DWORD *)&MasterIrp->Type;

// 查找进程对象
v8 = PsLookupProcessByProcessId((HANDLE)pid, &Process);

// 打开进程并终止
ObOpenObjectByPointer(Process, ...);
ZwTerminateProcess(ProcessHandle, 0);
```

**漏洞**：
- 任何管理员用户都可以终止任意进程
- 无需进一步权限验证

## 5. BYOVD 漏洞总结

| 漏洞类型 | 严重程度 | 描述 |
|---------|---------|------|
| **BYOVD (Bring Your Own Vulnerable Driver)** | CRITICAL | 驱动使用内核扫描技术在不同 Windows 版本上定位和调用内部 API |
| 任意进程终止 | CRITICAL | IOCTL 0x222440 可被管理员用户利用终止任意进程 |
| 权限检查不足 | HIGH | 仅检查管理员权限，未验证调用来源 |

## 6. 漏洞利用条件

1. **攻击者需要**:
   - 管理员权限
   - 能够发送 IOCTL 请求到驱动设备 `\Device\ksapi64_dev`

2. **影响**:
   - 可终止系统关键进程导致 DoS
   - 可配合其他漏洞实现提权

## 7. 修复建议

1. **移除 BYOVD 功能**:
   - 删除版本检测和内核扫描代码
   - 不使用未文档化的内部 API

2. **加强权限验证**:
   - 使用 `SeValidSecurityDescriptor` 验证调用者权限
   - 检查调用模式 (Kernel vs User)
   - 验证请求来源是否可信

3. **进程终止保护**:
   - 添加白名单机制保护关键系统进程
   - 记录所有终止操作到审核日志

## 8. 结论

**ksapi64_del.sys 存在明确的 BYOVD 漏洞**

该驱动包含：
1. Windows 版本检测代码
2. 内核模式字节模式扫描
3. 版本特定的内核函数定位
4. 任意进程终止功能

这些特征与 BYOVD (Bring Your Own Vulnerable Driver) 攻击模式完全吻合，攻击者可以利用该驱动终止任意进程或实现本地提权。

---
**分析完成**
