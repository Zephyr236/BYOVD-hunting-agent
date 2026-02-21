# CcProtect.sys BYOVD 漏洞分析报告

## 1. 基本信息

- **文件名**: CcProtect.sys
- **文件路径**: C:\Users\user\Desktop\BYOVD\CcProtect.sys
- **驱动入口点**: 0x28860 (DriverEntry)
- **IOCTL分发函数**: 0x28630 (sub_28630)

## 2. 驱动架构分析

### 2.1 导出的函数

驱动注册了以下IRP处理函数：
- `MajorFunction[0]` (IRP_MJ_CREATE): sub_285C0
- `MajorFunction[2]` (IRP_MJ_CLOSE): sub_28600  
- `MajorFunction[14]` (IRP_MJ_DEVICE_CONTROL): sub_28630

### 2.2 导入的危险API

| 函数地址 | 函数名 | 用途 |
|---------|--------|------|
| 0x164a0 | ZwTerminateProcess | 终止进程 |

## 3. 发现的安全问题

### 3.1 严重漏洞: 任意进程终止 (CVE-2025-XXXX)

**漏洞位置**: 
- sub_152B0 (地址: 0x152B0)
- sub_15370 (地址: 0x15370)

**触发IOCTL码**:
- 0x800024B4 → sub_15230 → sub_152B0 (终止进程)
- 0x800024B0 → sub_15230 → sub_15370 (终止进程变种)

**漏洞描述**:
sub_152B0 函数允许任意用户态进程通过IOCTL调用终止目标进程。该函数仅验证：
- ProcessId != 0
- ProcessId != 4 (System进程)

**没有任何权限校验**! 任何低权限用户都可以终止系统任意进程。

**漏洞代码** (sub_152B0):
```c
__int64 __fastcall sub_152B0(HANDLE ProcessId)
{
  // 仅检查 ProcessId 不为 0 和 4
  if ( !(_DWORD)ProcessId || (_DWORD)ProcessId == 4 )
    return 3221225485LL;
  
  // 获取进程对象
  v1 = PsLookupProcessByProcessId((HANDLE)(unsigned int)ProcessId, &Process);
  
  // 打开进程句柄
  v1 = ObOpenObjectByPointer(Process, 0x200u, 0, 0x1FFFFFu, 0, 0, &ProcessHandle);
  
  // 终止进程 - 无任何权限检查!
  v1 = ZwTerminateProcess(ProcessHandle, 0);
}
```

**风险等级**: **严重 (Critical)**

### 3.2 中危漏洞: 动态系统调用解析

**漏洞位置**: sub_15370 (地址: 0x15370)

**漏洞描述**:
该函数尝试动态解析 ZwTerminateProcess 的地址，绕过通常的导入表检测：

```c
v4 = (_DWORD *)qword_277D8;
if ( !qword_277D8 && (v4 = (_DWORD *)sub_15490(L"KeServiceDescriptorTable"), (qword_277D8 = (__int64)v4) == 0)
    || !&ZwTerminateProcess
    || (_BYTE)ZwTerminateProcess != 0xB8
    || (v5 = *(unsigned int *)((char *)&ZwTerminateProcess + 1), (v5 & 0xFFFFC000) != 0)
    || !(_DWORD)v5
    || (v6 = (unsigned int)*v4, !*v4)
    || !*(_DWORD *)(v6 + 4 * v5) )
{
    v3 = -1073741823;
}
```

这种技术可以用于：
1. 绕过安全软件的API hook检测
2. 作为BYOVD攻击的一部分

**风险等级**: **高 (High)**

### 3.3 中危漏洞: 缺少IOCTL权限验证

**漏洞位置**: sub_28630 (IOCTL分发函数)

**漏洞描述**:
IOCTL处理函数没有检查调用者的权限级别（通过 ExGetPreviousMode 或类似方法），所有IOCTL都直接处理用户传入的参数。

## 4. IOCTL码分析

| IOCTL码 | 值 | 处理函数 | 功能 |
|---------|-----|----------|------|
| 0x80002190 | -2147475440 | sub_12C10 | 键操作 |
| 0x80002194 | -2147475436 | sub_12C10 | 键操作 |
| 0x800021A0 | -2147475424 | sub_10670 | 版本检测 |
| 0x800021B0 | -2147475408 | sub_10EB0 | 未知 |
| 0x80002324 | -2147475036 | sub_14A40 | 文件操作 |
| 0x8000232C | -2147475028 | sub_14DD0 | 验证操作 |
| 0x80002330 | -2147475024 | sub_14DD0 | 验证操作 |
| 0x800024B0 | -2147474896 | sub_15370 | 终止进程(变种) |
| 0x800024B4 | -2147474892 | sub_152B0 | **终止任意进程** |

## 5. BYOVD利用可行性分析

### 5.1 BYOVD漏洞确认: **是**

该驱动存在以下BYOVD相关特征：

1. **任意进程终止能力**: 攻击者可以利用此驱动终止安全软件进程
2. **动态系统调用解析**: sub_15370 尝试动态获取 ZwTerminateProcess，绕过常规检测
3. **无权限验证**: 任何用户态程序都可以触发这些危险操作
4. **注册表写入**: 驱动向注册表写入数据，可能被用于持久化

### 5.2 利用场景

攻击者可以：
1. 加载该驱动 (需要管理员权限或通过签名漏洞)
2. 使用IOCTL 0x800024B4终止杀软/EDR进程
3. 然后执行恶意代码

## 6. 修复建议

### 6.1 必须修复

1. **添加权限校验**: 在所有IOCTL处理函数中添加权限检查
   ```c
   KPROCESSOR_MODE RequestorMode = ExGetPreviousMode();
   if (RequestorMode != KernelMode) {
       // 拒绝用户态直接调用
       return STATUS_ACCESS_DENIED;
   }
   ```

2. **验证调用者权限**: 使用 PsGetCurrentProcessToken 或类似方法验证调用者是否具有SeDebugPrivilege

3. **添加进程白名单**: 只允许终止特定白名单进程

### 6.2 建议修复

1. 移除动态系统调用解析代码
2. 添加日志记录功能
3. 实现更严格的输入验证

## 7. 结论

**CcProtect.sys 存在严重的BYOVD漏洞**。该驱动可以被恶意软件利用来：
1. 终止任意进程 (包括安全软件)
2. 绕过安全软件的API检测
3. 在系统上建立持久化

**风险等级: 严重**

---

*分析日期: 2025年*
*分析工具: IDA Pro*
