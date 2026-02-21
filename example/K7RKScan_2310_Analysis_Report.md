# K7RKScan_2310.sys BYOVD漏洞分析报告

## 文件信息
- **文件路径**: C:\Users\user\Desktop\BYOVD\K7RKScan_2310.sys
- **架构**: x64 (metapc-64)
- **驱动入口点**: 0x140001a60 (DriverEntry)

---

## 1. 危险API导入分析

该驱动导入了以下危险API：

| API地址 | 函数名 | 用途 |
|---------|--------|------|
| 0x1400050f8 | ZwTerminateProcess | 终止进程 |
| 0x1400050d8 | PsLookupProcessByProcessId | 根据PID查找进程 |
| 0x1400050e8 | PsGetProcessImageFileName | 获取进程名 |
| 0x1400050d0 | ObOpenObjectByPointer | 获取对象指针 |
| 0x1400050c8 | PsInitialSystemProcess | 获取系统初始进程 |
| 0x1400050c0 | MmIsAddressValid | 内存地址有效性检查 |

---

## 2. 关键危险函数分析

### 2.1 子函数 sub_140001680 (地址: 0x140001680)

**功能**: 根据进程ID终止进程

**反编译代码关键部分**:
```c
NTSTATUS __fastcall sub_140001680(HANDLE ProcessId)
{
  // 1. 根据PID查找进程
  v1 = PsLookupProcessByProcessId((HANDLE)(unsigned int)ProcessId, &Process);
  
  // 2. 获取进程映像名称
  Str1 = (const char *)PsGetProcessImageFileName(Process);
  
  // 3. 检查是否为保护进程
  if ( !stricmp(Str1, "csrss.exe")
    || !stricmp(Str1, "smss.exe")
    || !stricmp(Str1, "lsass.exe")
    || !stricmp(Str1, "winlogon.exe")
    || !stricmp(Str1, "svchost.exe")
    || ... )
  {
    v1 = -1073741790;  // 拒绝终止
  }
  else
  {
    // 4. 检查是否为保护进程
    SystemRoutineAddress = MmGetSystemRoutineAddress("PsIsProtectedProcess");
    if ( SystemRoutineAddress && SystemRoutineAddress(Process) )
    {
      v1 = -1073740014;  // 拒绝终止
    }
    else
    {
      // 5. 终止进程
      v1 = ObOpenObjectByPointer(Process, 0, 0, 0, 0, 0, &ProcessHandle);
      if ( v1 >= 0 )
        v1 = ZwTerminateProcess(ProcessHandle, 0);
    }
  }
}
```

**存在的保护措施**:
- 禁止终止系统关键进程 (csrss.exe, smss.exe, lsass.exe, winlogon.exe, svchost.exe)
- 使用 PsIsProtectedProcess 检查保护进程
- 使用 IsProtectedProcessLight 检查轻量级保护进程

---

## 3. IOCTL处理分析

### 3.1 DriverEntry 设置 (0x140001a60)

```c
DriverObject->MajorFunction[0] = sub_140001E50;   // IRP_MJ_CREATE
DriverObject->MajorFunction[2] = sub_140001E50;   // IRP_MJ_CLOSE
DriverObject->MajorFunction[14] = sub_140001F40;  // IRP_MJ_DEVICE_CONTROL
```

### 3.2 IRP_MJ_DEVICE_CONTROL 处理函数 sub_140001F40

该函数是一个大型switch语句处理多种IOCTL码。关键调用在:
- **地址 0x14000287f**: 调用 sub_140001680 终止进程

**IOCTL 0x1100 (2236416)**:
- 从用户模式接收 ProcessId
- 直接传递给 sub_140001680
- **无权限验证**

### 3.3 IRP_MJ_CREATE 权限检查 (sub_140001E50)

```c
__int64 __fastcall sub_140001E50(__int64 a1, __int64 Irp)
{
  // 检查调用者是否为管理员
  if ( !n2 )  // 首次打开设备
  {
    SeCaptureSubjectContext(&SubjectContext);
    SeLockSubjectContext(&SubjectContext);
    PrimaryToken = SubjectContext.PrimaryToken;
    if ( SubjectContext.ClientToken )
      PrimaryToken = SubjectContext.ClientToken;
    if ( PrimaryToken )
      IsAdmin = SeTokenIsAdmin(PrimaryToken);
    
    if ( !IsAdmin )
    {
      DbgPrint("K7RKScan: Unauthorized attempt to open driver.\n");
      v4 = -1073741790;  // ACCESS_DENIED
      goto LABEL_15;
    }
  }
}
```

**问题**: 权限检查只在设备打开时执行，IOCTL处理时没有再次验证。

---

## 4. BYOVD漏洞发现

### 4.1 漏洞概述

**漏洞类型**: BYOVD (Bring Your Own Vulnerable Driver) - 权限提升/进程终止

**漏洞位置**: 
- 函数: sub_140001680 (0x140001680)
- IOCTL处理: sub_140001F40 (0x140001F40) 的 case 0x1100 分支

### 4.2 漏洞详细说明

1. **权限验证缺失**:
   - IRP_MJ_CREATE 时检查管理员权限
   - IRP_MJ_DEVICE_CONTROL 时**未验证**调用者权限
   - 任何成功打开设备句柄的进程都可以发送IOCTL请求

2. **参数校验不足**:
   - 直接使用用户传入的 ProcessId
   - 未验证 ProcessId 是否为0（系统进程）或有效值

3. **攻击面**:
   - 攻击者需要先打开设备句柄
   - 打开设备句柄需要管理员权限
   - **但**: 一旦获得句柄，可以终止任意非保护进程

### 4.3 利用可行性分析

| 项目 | 说明 |
|------|------|
| 利用前提 | 需要管理员权限打开设备 |
| 影响范围 | 可终止任意非保护进程 |
| 系统进程保护 | 有 (csrss.exe, smss.exe, lsass.exe等) |
| 杀软进程保护 | 有 (PsIsProtectedProcess) |
| 利用难度 | 低 |
| 权限要求 | 管理员 |

**实际威胁**:
1. 攻击者可以终止杀毒软件/安全产品进程
2. 攻击者可以终止其他安全工具
3. 虽然不能直接终止系统关键进程，但可以终止大多数用户态进程

---

## 5. 风险评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 严重性 | **高** | 可被用于终止安全软件 |
| 可利用性 | **中** | 需要管理员权限，但利用简单 |
| 影响范围 | **中** | 只能终止非保护进程 |
| 总体风险 | **高** | BYOVD类漏洞 |

---

## 6. 修复建议

1. **IOCTL权限验证**:
   - 在每个IOCTL处理函数中重新验证调用者权限
   - 使用 SeCaptureSubjectContext 获取当前线程的安全上下文

2. **参数校验**:
   - 验证 ProcessId 不为0
   - 验证 ProcessId 在合理范围内
   - 检查是否为当前进程（防止自杀）

3. **审计日志**:
   - 记录所有进程终止操作
   - 记录调用者信息

4. **最小权限原则**:
   - 考虑使用更低权限的Token进行操作
   - 避免使用 SYSTEM 权限执行不必要的操作

---

## 7. 结论

K7RKScan_2310.sys 存在 **BYOVD (Bring Your Own Vulnerable Driver)** 类型漏洞。

该驱动设计用于终止进程，但权限验证不完善：
- 仅在设备打开时验证管理员权限
- IOCTL处理时未再次验证
- 可被已获得管理员权限的攻击者利用来终止安全软件进程

虽然该驱动有一些进程保护机制，但仍然可以被滥用作为攻击向量。建议供应商修复权限验证缺失问题。
