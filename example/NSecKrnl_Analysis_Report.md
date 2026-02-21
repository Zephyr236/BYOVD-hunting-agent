# NSecKrnl.sys BYOVD Vulnerability Analysis Report

## Basic Driver Information
- **Filename**: NSecKrnl.sys
- **Architecture**: x64 (metapc-64)
- **DriverEntry**: 0x140009000

## Dangerous API Import Analysis
Found the following dangerous API imports:
- `ZwTerminateProcess` - Can terminate processes
- `PsLookupProcessByProcessId` - Can lookup process by PID
- `ObOpenObjectByPointer` - Can get object pointer
- `PsGetProcessId` - Get process ID
- `PsGetCurrentProcessId` - Get current process ID
- `IoGetCurrentProcess` - Get current process object
- `ObRegisterCallbacks` - Register callbacks

## IOCTL Handler Analysis

### IRP_MJ_DEVICE_CONTROL (0x14) - sub_140001030

| IOCTL Code (hex) | IOCTL Code (dec) | Function | Permission Check |
|------------------|------------------|----------|------------------|
| 0x2244E8 | 2246872 | Remove PID from whitelist | NO |
| 0x2244EC | 2246876 | Query if PID is in whitelist | NO |
| 0x2244F0 | 2246880 | **Terminate arbitrary process** | NO |

## Vulnerability Details

### Vulnerability 1: Arbitrary Process Termination (CRITICAL)

**Location**: sub_1400013E8

**Function Code**:
```c
char __fastcall sub_1400013E8(void *ProcessId)
{
  HANDLE ProcessHandle;
  PEPROCESS Process;
  
  Process = 0;
  ProcessHandle = 0;
  if ( PsLookupProcessByProcessId(ProcessId, &Process) >= 0
    && ObOpenObjectByPointer(Process, 0x200u, 0, 1u, (POBJECT_TYPE)PsProcessType, 0, &ProcessHandle) >= 0 )
  {
    ZwTerminateProcess(ProcessHandle, 0);
    ZwClose(ProcessHandle);
  }
  if ( Process )
    ObfDereferenceObject(Process);
  return 0;
}
```

**Vulnerability Analysis**:
- This function directly accepts ProcessId from user mode
- Uses `PsLookupProcessByProcessId` to convert PID to EPROCESS structure
- Uses `ObOpenObjectByPointer` to get process handle
- Calls `ZwTerminateProcess` to terminate the process
- **NO permission check at all! Any user can terminate any system process!**

**IOCTL Code**: 0x2244F0 (decimal: 2246880)

### Vulnerability 2: Whitelist Management Without Permission Check

**Location**: sub_1400012B8, sub_140001240, sub_140001614

| Function | Functionality | Issue |
|----------|---------------|-------|
| sub_1400012B8 | Add PID to whitelist | No permission check |
| sub_140001240 | Add PID to whitelist | No permission check |
| sub_140001614 | Remove PID from whitelist | No permission check |

The whitelist is intended to protect certain processes from being terminated, but due to:
1. Whitelist can be arbitrarily modified via IOCTL
2. Terminate process IOCTL does not check caller permissions
3. Attackers can first add target to whitelist, then call terminate

## Exploitation Feasibility

### Exploitation Conditions
- **No privileges required**: Any user-mode program can call these IOCTLs
- **Scope**: Can terminate any system process including critical system processes

### Exploitation Steps
1. Open device `\Device\NSecKrnl`
2. Call IOCTL 0x2244F0 with target PID
3. Target process will be forcefully terminated

## Risk Assessment

| Item | Rating |
|------|--------|
| Severity | **CRITICAL** |
| Exploitation Complexity | **Extremely Low** |
| Scope | **Full System** |
| Privilege Required | **Standard User** |

## Remediation Suggestions

1. **Add Permission Check**: Verify caller privileges before terminating processes
2. **Input Validation**: Check if PID is a valid value
3. **Restrict Callers**: Only allow admin or SYSTEM privileges to call sensitive IOCTLs
4. **Audit Logging**: Log all termination operations

## Conclusion

**NSecKrnl.sys has a critical BYOVD vulnerability that can be exploited by standard users to terminate arbitrary system processes without any privilege checks.**
