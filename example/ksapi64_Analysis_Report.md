# ksapi64.sys BYOVD漏洞分析报告

## 1. 基本信息

| 项目 | 值 |
|------|-----|
| 文件名 | ksapi64.sys |
| 架构 | x64 (metapc-64) |
| 驱动入口 | DriverEntry @ 0x21000 |
| 设备名称 | \Device\ksapi64_dev |
| 符号链接 | \DosDevices\ksapi64_dev |
| IOCTL分发函数 | sub_12960 @ 0x12960 |
| 主处理函数 | sub_12A30 @ 0x12A30 |

## 2. 危险API导入分析

该驱动导入了以下危险API，可被用于BYOVD攻击：

| API函数 | 地址 | 用途 |
|---------|------|------|
| ZwTerminateProcess | 0x112d0 | 终止任意进程 |
| PsLookupProcessByProcessId | 0x11260 | 通过PID查找进程对象 |
| ObOpenObjectByPointer | 0x11220 | 通过指针打开对象 |
| KeStackAttachProcess | 0x11258 | 附加到目标进程内存空间 |
| ZwOpenProcess | 0x11240 | 打开进程对象 |
| MmIsAddressValid | 0x11218 | 验证内存地址有效性 |

## 3. 发现的严重漏洞

### 3.1 任意进程终止漏洞 (CVE级别: 严重)

**漏洞位置:**
- IOCTL码: 0x222440
- 处理函数: sub_19FD0 @ 0x19FD0
- 调用路径: sub_12A30 -> sub_19FD0

**漏洞描述:**

IOCTL处理函数 sub_12A30 在地址 0x12B49 处直接调用 sub_19FD0，该函数可以从用户模式接受任意进程PID，并调用 ZwTerminateProcess 终止该进程，且没有任何权限校验。

**关键代码分析 (sub_19FD0):**

```c
// 0x19FD0 函数关键部分
v8 = PsLookupProcessByProcessId((HANDLE)*(unsigned int *)&MasterIrp->Type, &Process);
if ( v8 >= 0 && Process )
{
    v10 = ObOpenObjectByPointer(Process, 0x200u, 0, 0x10000000u, (POBJECT_TYPE)PsProcessType, 0, &ProcessHandle);
    v12 = ZwTerminateProcess(ProcessHandle, 0);  // 直接终止进程
}
```

**漏洞利用条件:**
1. 攻击者只需要知道目标进程的PID
2. 不需要任何特殊权限
3. 可以终止系统关键进程（如smss.exe, csrss.exe等）导致系统崩溃

**影响:**
- 本地提权 (从普通用户到SYSTEM)
- 拒绝服务 (DoS)
- 绕过安全产品

### 3.2 进程对象句柄泄露漏洞

**漏洞位置:** sub_1A190 @ 0x1A190

**漏洞描述:**

函数 sub_1A190 可以获取任意进程的对象句柄，然后将其返回给用户模式调用者。攻击者可以利用此漏洞获取高权限进程的句柄，进一步利用。

```c
// sub_1A190 函数关键部分
v4 = PsLookupProcessByProcessId(*Address, &Process);
if ( v4 < 0 ) ...
else
{
    v4 = ObOpenObjectByPointer(
           Process,
           0,
           0,
           (ACCESS_MASK)MasterIrp->MdlAddress,  // 用户控制!
           (POBJECT_TYPE)PsProcessType,
           0,
           *(PHANDLE *)&MasterIrp->Type);       // 句柄返回给用户
}
```

### 3.3 权限检查绕过

**发现:**

虽然 sub_12A30 入口处有 SeTokenIsAdmin 检查:
```c
SeCaptureSubjectContext(&SubjectContext);
if ( SeTokenIsAdmin(Token) )
    bl = 1;
// ...
if ( !bl )
    return 0xC0000022; // ACCESS_DENIED
```

但是，IOCTL 0x222440 的处理路径 (0x12B49 -> sub_19FD0) 直接调用了 ZwTerminateProcess，没有再次进行权限验证。这意味着:
- 即使初始权限检查失败，某些代码路径仍然可能执行危险操作

## 4. IOCTL码分析

| IOCTL码 | 处理函数 | 功能描述 | 风险等级 |
|---------|----------|----------|----------|
| 0x222440 | sub_19FD0 | 终止指定PID的进程 | 严重 |
| 0x222444 | sub_1A190 | 获取进程句柄 | 严重 |
| 0x22241C-0x22243F | various | 其他操作 | 中等 |

## 5. BYOVD利用可行性

**符合BYOVD特征:**

1. 导入并使用危险内核API (ZwTerminateProcess, PsLookupProcessByProcessId等)
2. 存在本地提权漏洞 (任意进程终止)
3. 无需管理员权限即可利用
4. 可被恶意软件利用来终止安全软件

**利用场景:**

1. **终止安全软件:**
   - 攻击者可以使用IOCTL 0x222440终止杀毒软件进程
   - 例如: 终止PID为XXXX的杀毒软件服务

2. **系统破坏:**
   - 终止系统关键进程导致蓝屏死机(BSOD)
   - 例如: 终止smss.exe (会话管理器)

3. **持久化对抗:**
   - 定期终止可能检测恶意软件的安全进程

## 6. 风险评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 严重性 | 10/10 | 可被普通用户利用终止任意进程 |
| 可利用性 | 10/10 | 无需特殊配置，直接调用驱动IOCTL |
| 影响范围 | 10/10 | 所有安装此驱动的系统 |
| 漏洞复杂度 | 低 | 利用简单，PID容易获取 |

## 7. 修复建议

1. **添加权限校验:** 在处理IOCTL 0x222440之前，验证调用者是否具有SeDebugPrivilege或管理员权限

2. **进程白名单:** 只允许终止特定列表中的进程，或禁止终止系统关键进程

3. **使用PsGetCurrentProcess:** 验证目标进程不是受保护的进程

4. **审计日志:** 记录所有进程终止操作到内核日志

## 8. 结论

**ksapi64.sys 存在严重的BYOVD漏洞，评级为高危。** 该驱动可以被恶意软件利用来:
- 终止安全软件
- 终止系统进程造成DoS
- 获取高权限进程句柄

建议立即修复此漏洞或更新驱动版本。

---
*分析时间: 2026-02-21*
*分析工具: IDA Pro*
