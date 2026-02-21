# BdApiUtil64.sys BYOVD漏洞分析报告

## 1. 基本信息

| 项目 | 描述 |
|------|------|
| 文件名 | BdApiUtil64.sys |
| 文件路径 | C:\Users\user\Desktop\BYOVD\BdApiUtil64.sys |
| 架构 | x64 (metapc-64) |
| 驱动类型 | Windows 内核驱动 |
| 设备名称 | \Device\BdApiUtil |
| 符号链接 | \DosDevices\BdApiUtil |

## 2. 导出函数分析

### 2.1 驱动入口点
- **DriverEntry**: 0x28860
- **DriverUnload**: sub_287C0

### 2.2 IRP处理函数
| IRP Major Function | 地址 | 功能描述 |
|-------------------|------|----------|
| IRP_MJ_CREATE (0) | sub_285C0 | 创建设备对象 |
| IRP_MJ_CLOSE (2) | sub_28600 | 关闭设备对象 |
| IRP_MJ_DEVICE_CONTROL (0xE) | sub_28630 | IOCTL分发处理 |

## 3. IOCTL处理分析

### 3.1 IOCTL码与处理函数映射

| IOCTL码 | 十六进制 | 处理函数 | 功能 |
|---------|----------|----------|------|
| 0x800024B4 | -2147474252 | sub_15230 -> sub_152B0 | **终止进程** |
| 0x800024B0 | -2147474248 | sub_15230 -> sub_15370 | **终止进程(动态函数调用)** |
| 0x80002324 | -2147474660 | sub_14A40 | **创建文件** |
| 0x8000232C | -2147474652 | sub_14DD0 | 过滤器枚举 |
| 0x80002330 | -2147474648 | sub_14DD0 | 过滤器枚举 |
| 0x80002190 | -2147480688 | sub_10670 | 系统版本检测 |
| 0x800021A0 | -2147480672 | sub_10EB0 | 关闭句柄 |
| 0x800024B8 | -2147474248 | sub_12C10 | 通用处理 |
| 其他 | -2147475456~5444 | sub_12C10 | 通用处理 |

## 4. 发现的安全漏洞

### 4.1 严重漏洞：未授权进程终止 (CVE级别: 严重)

**漏洞位置**: 
- sub_152B0 (地址: 0x152B0)
- sub_15370 (地址: 0x15370)

**漏洞描述**:
驱动提供了直接终止任意进程的功能，没有任何权限验证。

**漏洞代码 (sub_152B0)**:
```c
__int64 __fastcall sub_152152B0(HANDLE ProcessId)
{
  // ...
  if ( !(_DWORD)ProcessId || (_DWORD)ProcessId == 4 )  // 仅保护PID 0和4
    return 3221225485LL;
  v1 = PsLookupProcessByProcessId((HANDLE)(unsigned int)ProcessId, &Process);
  if ( !v1 )
  {
    v1 = ObOpenObjectByPointer(Process, 0x200u, 0, 0x1FFFFFu, 0, 0, &ProcessHandle);
    if ( v1 >= 0 )
      v1 = ZwTerminateProcess(ProcessHandle, 0);  // 直接终止进程
  }
  // ...
}
```

**影响**:
- 任何用户模式程序都可以发送IOCTL 0x800024B4或0x800024B0来终止系统中的任意进程
- 可以被恶意软件利用来终止安全软件（杀毒软件、安全工具等）
- 可以终止系统关键进程导致蓝屏或系统不稳定

**风险等级**: **严重 (Critical)**

### 4.2 高危漏洞：任意文件创建

**漏洞位置**: sub_14A40 (地址: 0x14A40)

**漏洞描述**:
驱动允许用户模式程序创建任意文件，可能导致:
- 恶意文件创建
- 覆盖系统关键文件
- 提权利用

**风险等级**: **高危 (High)**

### 4.3 高危漏洞：缺乏权限校验

**漏洞描述**:
所有IOCTL处理函数都缺少以下安全检查:
- SeAccessCheck 权限验证
- 客户端会话验证
- 调用者令牌检查
- 参数合法性验证

**风险等级**: **高危 (High)**

### 4.4 中危漏洞：动态函数解析绕过

**漏洞位置**: sub_15370 (地址: 0x15370)

**漏洞描述**:
该函数通过读取 `KeServiceDescriptorTable` 动态解析 `ZwTerminateProcess`:
```c
v4 = (_DWORD *)qword_277D8;
v4 = (_DWORD *)sub_15490(L"KeServiceDescriptorTable");
// ... 动态计算函数地址并调用
v7 = ((__int64 (__fastcall *)(HANDLE, _QWORD))*(unsigned int *)(v6 + 4 * v5))(Handle, 0);
```

这种技术可以绑过某些安全软件的Inline Hook检测。

**风险等级**: **中危 (Medium)**

## 5. BYOVD (Bring Your Own Vulnerable Driver) 利用分析

该驱动完全符合BYOVD漏洞的特征:

1. **可信内核驱动**: 作为合法驱动程序存在,通常被安全软件信任
2. **危险操作**: 直接调用 ZwTerminateProcess 等高危内核API
3. **无权限校验**: 任何用户态程序都可以触发这些危险操作
4. **可被利用**: 恶意软件可以利用此驱动终止安全软件

## 6. 漏洞利用条件

| 条件 | 说明 |
|------|------|
| 需要加载驱动 | 需要管理员权限加载驱动 |
| 设备访问 | 需要打开 \\Device\BdApiUtil 设备 |
| IOCTL发送 | 需要知道具体的IOCTL码 |

## 7. 修复建议

1. **添加权限验证**: 在每个IOCTL处理函数中添加调用者权限检查
2. **限制进程终止**: 仅允许终止特定白名单进程或调用者创建的进程
3. **添加访问控制**: 使用 SeAccessCheck 验证调用者权限
4. **输入验证**: 对所有用户输入进行严格的合法性验证

## 8. 结论

BdApiUtil64.sys 是一个存在严重安全漏洞的Windows内核驱动，主要问题是：

1. **未授权进程终止** - 可被利用来终止任意进程包括安全软件
2. **缺乏权限校验** - 任何用户态程序都可以触发危险操作
3. **任意文件创建** - 可能被利用进行权限提升

该驱动符合典型的BYOVD漏洞特征，建议立即修复或停止使用。

---
*报告生成时间: 2026-02-21*
*分析工具: IDA Pro*
