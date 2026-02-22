import asyncio
from fastmcp import Client
from anthropic import Anthropic
from dotenv import load_dotenv
import os
import subprocess
from pathlib import Path
import json
import secrets
import time
import sys
import win32gui
import win32con
import win32process
import psutil

load_dotenv(override=True)
context7_encryption_key = os.getenv(
    "CONTEXT7_ENCRYPTION_KEY", secrets.token_hex(32)  # 默认生成64字符的随机密钥
)
config = {
    "mcpServers": {
        "MiniMax": {
            "command": "uvx",
            "args": ["minimax-coding-plan-mcp", "-y"],
            "env": {
                "MINIMAX_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
                "MINIMAX_API_HOST": "https://api.minimaxi.com",
            },
        },
        # "context7": {
        #     "command": "cmd.exe",
        #     "args": [
        #         "/C",
        #         "npx -y @upstash/context7-mcp --api-key 'ctx' 2>NUL",
        #     ],
        #     "env": {"CLIENT_IP_ENCRYPTION_KEY": context7_encryption_key},
        # },
        "ida-multi-mcp": {
            "args": ["-m", "ida_multi_mcp"],
            "command": "C:\\Users\\user\\Desktop\\IDA Professional 9.1\\python311\\python.exe",
        },
        # "ida-cmd": {
        #     "command": "python",
        #     "args": ["C:\\Users\\user\\Desktop\\ida_tool.py"],
        # },
    }
}
client = Anthropic(
    api_key=os.getenv("ANTHROPIC_API_KEY"), base_url=os.getenv("ANTHROPIC_BASE_URL")
)
MODEL = os.environ["MODEL_ID"]
TOOLS = []
launch_ida_instance_TOOL = {
    "name": "launch_ida_instance",
    "description": "Launches a standalone IDA Pro instance locally to automatically analyze a specified file.\nThis tool attempts to run IDA in a separate process, so it will not terminate when the Python script ends.\nIt is recommended to use the full path to specify ida.exe to avoid PATH issues.",
    "input_schema": {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "The full path to the file to be analyzed, e.g., C:\\Users\\user\\Desktop\\CcProtect.sys",
            },
            "ida_path": {
                "type": "string",
                "description": "The full path to ida.exe or ida64.exe. Defaults to 'ida.exe' (will be searched for in the PATH).",
                "default": "ida.exe",
            },
        },
        "required": ["file_path"],
    },
}
todo_list = [
    {
        "id": 1,
        "description": "启动IDA Pro分析驱动文件",
        "status": "waiting",
        "details": {},
    },
    {
        "id": 2,
        "description": "获取IDA实例ID用于后续分析",
        "status": "waiting",
        "details": {},
    },
        {
        "id": 3,
        "description": "获取导入的函数进行初步分析",
        "status": "waiting",
        "details": {},
    },
    {
        "id": 4,
        "description": "查找DriverEntry函数（入口点）",
        "status": "waiting",
        "details": {
            "method": "使用list_funcs工具列出所有函数并查找DriverEntry",
            "alternative": "使用find_regex搜索DriverEntry字符串",
        },
    },
    {
        "id": 5,
        "description": "分析DriverEntry中的IRP_MJ_DEVICE_CONTROL设置",
        "status": "waiting",
        "details": {
            "target": "查找IRP_MJ_DEVICE_CONTROL分发函数地址",
            "method": "反编译DriverEntry函数并查找MajorFunction[IRP_MJ_DEVICE_CONTROL]赋值",
        },
    },
    {
        "id": 6,
        "description": "定位IOCTL分发函数并反编译分析",
        "status": "waiting",
        "details": {
            "target": "获取IOCTL分发函数地址并反编译",
            "method": "使用decompile工具分析分发函数逻辑",
        },
    },
    {
        "id": 7,
        "description": "查找危险API调用（ZwTerminateProcess, ZwWriteVirtualMemory等）",
        "status": "waiting",
        "details": {
            "dangerous_apis": [
                "ZwTerminateProcess",
                "NtTerminateProcess",
                "TerminateProcess",
                "ZwWriteVirtualMemory",
                "NtWriteVirtualMemory",
                "MmWritePhysicalMemory",
                "ZwReadVirtualMemory",
                "NtReadVirtualMemory",
                "MmReadPhysicalMemory",
            ],
            "method": "使用find_regex搜索危险API调用",
        },
    },
    {
        "id": 8,
        "description": "分析IOCTL处理函数：提取IOCTL码和分支处理函数",
        "status": "waiting",
        "details": {
            "steps": [
                "从分发函数中提取IOCTL码",
                "查找每个IOCTL对应的处理函数",
                "反编译每个处理函数进行深入分析",
            ]
        },
    },
    {
        "id": 9,
        "description": "检查权限校验和内存安全问题",
        "status": "waiting",
        "details": {
            "checks": [
                "权限校验缺失",
                "输入参数验证不足",
                "缓冲区溢出",
                "整数溢出",
                "空指针解引用",
            ]
        },
    },
    {
        "id": 10,
        "description": "生成BYOVD漏洞分析报告",
        "status": "waiting",
        "details": {
            "report_sections": [
                "发现的安全问题",
                "风险等级评估",
                "利用可行性分析",
                "修复建议",
            ],
            "method": "使用write_file以markdown格式生成报文",
        },
    },
    {
        "id": 11,
        "description": "关闭所有IDA实例并清理资源",
        "status": "waiting",
        "details": {
            "steps": ["获取所有运行的IDA实例", "优雅关闭每个实例", "确认所有实例已关闭"]
        },
    },
]

# 定义查询todolist的tool
get_todo_list_TOOL = {
    "name": "get_todo_list",
    "description": "Retrieve the current todo list, including ID, description, status, and details of each task",
    "input_schema": {
        "type": "object",
        "properties": {
            "filter_status": {
                "type": "string",
                "description": "Optional, filter tasks by status, allowed values: all, waiting, completed, failed",
                "default": "all",
            }
        },
        "required": [],
    },
}

# 定义更新todolist的tool
update_todo_item_TOOL = {
    "name": "update_todo_item",
    "description": "Update the status and details of a specific item in the todo list",
    "input_schema": {
        "type": "object",
        "properties": {
            "item_id": {
                "type": "integer",
                "description": "The ID of the todo item to update",
            },
            "status": {
                "type": "string",
                "description": "New status of the todo item, allowed values: waiting, completed, failed",
                "enum": ["waiting", "completed", "failed"],
            },
            "details": {
                "type": "object",
                "description": "Optional details, can be any JSON object",
            },
        },
        "required": ["item_id", "status"],
    },
}

run_cmd = {
    "name": "run_cmd",
    "description": "Run a cmd command.",
    "input_schema": {
        "type": "object",
        "properties": {"command": {"type": "string"}},
        "required": ["command"],
    },
}

close_ida_gracefully_TOOL = {
    "name": "close_ida_gracefully",
    "description": "Gracefully close an IDA Pro process with the specified PID. Sends a WM_CLOSE message to IDA's main window, simulating clicking the close button, which triggers its normal exit process (such as prompting to save).",
    "input_schema": {
        "type": "object",
        "properties": {
            "pid": {
                "type": "integer",
                "description": "The process identifier (PID) of the IDA Pro process to close.",
            }
        },
        "required": ["pid"],
    },
}
write_file = {
    "name": "write_file",
    "description": "Write content to file.",
    "input_schema": {
        "type": "object",
        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        "required": ["path", "content"],
    },
}

TOOLS = TOOLS + [launch_ida_instance_TOOL]
TOOLS = TOOLS + [get_todo_list_TOOL, update_todo_item_TOOL]
TOOLS = TOOLS + [run_cmd]
TOOLS = TOOLS + [close_ida_gracefully_TOOL]
TOOLS = TOOLS + [write_file]
SYSTEM = f"""You are a BYOVD-hunting agent at {os.getcwd()}.
Use tools to solve tasks. Act, don't explain.
Use the todo tool to track progress on multi-step tasks. After completing each step, use update_todo_item to mark it as completed or failed.
Prefer tools over prose.
Perform internet searches when needed to gather information.
"""


def get_todo_list(filter_status: str = "all") -> dict[str, any]:
    """
    获取当前的待办事项列表
    """
    result = {
        "success": True,
        "todo_list": [],
        "summary": {"total": 0, "waiting": 0, "completed": 0, "failed": 0},
    }

    # 过滤任务
    if filter_status == "all":
        filtered_list = todo_list
    else:
        filtered_list = [item for item in todo_list if item["status"] == filter_status]

    # 计算统计信息
    for item in todo_list:
        result["summary"]["total"] += 1
        if item["status"] == "waiting":
            result["summary"]["waiting"] += 1
        elif item["status"] == "completed":
            result["summary"]["completed"] += 1
        elif item["status"] == "failed":
            result["summary"]["failed"] += 1

    # 准备返回的任务列表
    result["todo_list"] = filtered_list
    result["filter_status"] = filter_status

    return result


# 实现更新todolist的函数
def update_todo_item(item_id: int, status: str, details: dict = None) -> dict[str, any]:
    """
    更新待办事项列表中指定项目的状态和详细信息
    """
    result = {"success": False, "message": "", "updated_item": None}

    # 查找要更新的项目
    for item in todo_list:
        if item["id"] == item_id:
            # 更新状态
            old_status = item["status"]
            item["status"] = status

            # 更新详细信息（如果提供）
            if details is not None:
                item["details"] = details

            # 准备结果
            result["success"] = True
            result["message"] = f"待办事项ID {item_id} 已更新: {old_status} -> {status}"
            result["updated_item"] = item.copy()

            # 打印更新日志
            print(
                f"[TODO] 更新: ID={item_id}, 状态={old_status}->{status}, 描述={item['description']}"
            )

            return result

    # 如果没找到指定ID的项目
    result["message"] = f"未找到ID为 {item_id} 的待办事项"
    return result


def launch_ida_instance(file_path: str, ida_path: str = "ida.exe") -> dict[str, any]:
    """
    Launch an independent IDA Pro instance (not as a subprocess of the current process).
    The IDA process will detach from Python and will not be terminated even if Python exits.
    """
    result = {"success": False, "pid": None, "message": ""}
    cmd = [ida_path, "-A", file_path]
    try:
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        DETACHED_PROCESS = 0x00000008

        process = subprocess.Popen(
            cmd,
            shell=True,  # Using shell=True is often more stable
            stdout=subprocess.DEVNULL,  # No need to capture output
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
        )
        result["pid"] = process.pid
        result["success"] = True
        result["message"] = (
            f"Independent IDA instance started (PID: {process.pid})\n"
            f"File: {file_path}\n"
            f"Used IDA executable: {ida_path}\n"
            f"If no window appears, please check:\n"
            f"1. Whether ida_path is correct\n"
            f"2. Whether the current Python is running in a graphical session"
        )
        # Release subprocess tracking of the child process
        process._child_created = False

    except FileNotFoundError:
        result["message"] = f"Cannot find IDA executable: {ida_path}"
    except PermissionError:
        result["message"] = "Permission issue: Unable to start process"
    except Exception as e:
        result["message"] = f"Launch failed: {str(e)}"
    time.sleep(30)
    return result


def run_cmd(command: str) -> str:
    try:
        r = subprocess.run(
            command,
            shell=True,
            cwd=os.getcwd(),
            capture_output=True,
            text=True,
            timeout=120,
        )
        out = (r.stdout + r.stderr).strip()
        return out[:50000] if out else "(no output)"
    except subprocess.TimeoutExpired:
        return "Error: Timeout (120s)"


def find_main_window(pid):
    """根据 PID 找到进程的主窗口句柄（内部辅助函数）"""

    def enum_windows_callback(hwnd, windows):
        _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
        if found_pid == pid:
            # 过滤可见的主窗口（排除子窗口、工具栏等）
            if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                windows.append(hwnd)
        return True

    windows = []
    win32gui.EnumWindows(enum_windows_callback, windows)
    return windows[0] if windows else None  # 通常第一个就是主窗口


def close_ida_gracefully(pid: int) -> dict:
    """
    Gracefully close an IDA Pro process with the specified PID.

    Sends a WM_CLOSE message to IDA's main window, simulating clicking the close button,
    which triggers its normal exit process (such as prompting to save).

    Args:
        pid (int): The process identifier (PID) of the IDA Pro process to close.

    Returns:
        dict: Dictionary containing the operation result. Structure:
            {
                "success": bool,      # Whether the operation was successfully initiated (window found and message sent)
                "pid": int,           # The provided PID
                "window_found": bool, # Whether the corresponding main window was found
                "window_title": str | None, # Title of the found window (if successful)
                "message": str        # Detailed description of the operation result
            }

    Note:
        1. This tool only sends a close request and does not wait for or guarantee that the process will eventually exit.
        2. You can use the `ida-multi-mcp --list` command to find running IDA instances and their PIDs.
    """
    result = {
        "success": False,
        "pid": pid,
        "window_found": False,
        "window_title": None,
        "message": "",
    }

    # Optional: Check if the process is alive
    if not psutil.pid_exists(pid):
        result["message"] = (
            f"Error: Process with PID {pid} does not exist or has already exited."
        )
        return result

    hwnd = find_main_window(pid)
    if not hwnd:
        result["message"] = (
            f"Could not find the main window for PID {pid}. The process may not have a visible window or may not be IDA."
        )
        return result

    window_title = win32gui.GetWindowText(hwnd)
    result["window_found"] = True
    result["window_title"] = window_title

    # Send WM_CLOSE message, equivalent to clicking the X button, triggering IDA's normal shutdown process
    try:
        win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
        # Note: PostMessage is asynchronous and returns immediately.
        result["success"] = True
        result["message"] = (
            f"Successfully sent close signal to IDA window '{window_title}' (PID: {pid}). The program will prompt to save and exit normally."
        )
    except Exception as e:
        result["message"] = f"Error sending close message to window: {e}"

    return result

WORKDIR = Path.cwd()
def safe_path(p: str) -> Path:
    path = (WORKDIR / p).resolve()
    if not path.is_relative_to(WORKDIR):
        raise ValueError(f"Path escapes workspace: {p}")
    return path

def write_file(path: str, content: str) -> str:
    try:
        fp = safe_path(path)
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content)
        return f"Wrote {len(content)} bytes to {path}"
    except Exception as e:
        return f"Error: {e}"


def call_local_tool(tool_name: str, tool_input: dict) -> dict:
    """
    处理本地工具调用
    """
    # 原有的launch_ida_instance处理
    if tool_name == "launch_ida_instance":
        file_path = tool_input.get("file_path")
        ida_path = tool_input.get("ida_path", "ida.exe")
        if not file_path:
            return {"success": False, "message": "Missing file_path parameter"}
        return launch_ida_instance(file_path, ida_path)

    # 新增的TODO工具处理
    elif tool_name == "get_todo_list":
        filter_status = tool_input.get("filter_status", "all")
        return get_todo_list(filter_status)

    elif tool_name == "update_todo_item":
        item_id = tool_input.get("item_id")
        status = tool_input.get("status")
        details = tool_input.get("details")

        if item_id is None:
            return {"success": False, "message": "Missing item_id parameter"}
        if status is None:
            return {"success": False, "message": "Missing status parameter"}

        return update_todo_item(item_id, status, details)
    elif tool_name == "run_cmd":
        command = tool_input.get("command")
        return run_cmd(command)

    elif tool_name == "close_ida_gracefully":
        pid = tool_input.get("pid")
        return close_ida_gracefully(pid)
    elif tool_name == "write_file":
        path = tool_input.get("path")
        content = tool_input.get("content")
        return write_file(path, content)

    return {"success": False, "message": f"Unknown local tool: {tool_name}"}


def init_tools_list():

    client = Client(config)

    async def _get_tools_list():
        async with client:
            tools = await client.list_tools()
            for tool in tools:
                # fastmcp 的 Tool 有 .name, .description, .inputSchema
                # inputSchema 已经是 JSON Schema 格式，可以直接用

                TOOLS.append(
                    {
                        "name": tool.name,
                        "description": tool.description.strip(),  # 去掉多余换行
                        "input_schema": tool.inputSchema,  # 核心字段
                    }
                )
        return TOOLS

    return asyncio.run(_get_tools_list())


def call_tool(tool_name, tool_input):
    client = Client(config)

    async def _call_tool():
        async with client:
            result = await client.call_tool(tool_name, tool_input)
            return result

    return asyncio.run(_call_tool())


def agent_loop(messages: list):
    rounds_since_todo = 0
    while True:
        if rounds_since_todo >= 3 and messages:
            last = messages[-1]
            if last["role"] == "user" and isinstance(last.get("content"), list):
                last["content"].insert(
                    0,
                    {
                        "type": "text",
                        "text": "<reminder>Read and Update your todo.</reminder>",
                    },
                )
        response = client.messages.create(
            model=MODEL,
            system=SYSTEM,
            messages=messages,
            tools=TOOLS,
            max_tokens=8000,
        )
        # Append assistant turn
        messages.append({"role": "assistant", "content": response.content})
        # If the model didn't call a tool, we're done
        # print(response.content)
        if response.stop_reason != "tool_use":
            return
        # Execute each tool call, collect results
        results = []
        used_todo = False
        for block in response.content:
            if block.type == "text":
                print(f"text: {block.text}")
            if block.type == "thinking":
                print(f"thinking: {block.thinking}")
            if block.type == "tool_use":
                print(f"tool_use: {block.name}")
                try:
                    if block.name == "launch_ida_instance":
                        output = call_local_tool(block.name, block.input)
                    elif block.name == "update_todo_item":
                        output = call_local_tool(block.name, block.input)
                    elif block.name == "get_todo_list":
                        output = call_local_tool(block.name, block.input)
                    elif block.name == "run_cmd":
                        output = call_local_tool(block.name, block.input)
                    elif block.name == "close_ida_gracefully":
                        output = call_local_tool(block.name, block.input)
                    elif block.name == "write_file":
                        output = call_local_tool(block.name, block.input)
                    else:
                        output = call_tool(block.name, block.input)

                    # 处理工具调用成功的输出
                    if hasattr(output, "structured_content"):
                        content = output.structured_content
                        # 如果是字典或列表，转换为JSON字符串
                        if isinstance(content, (dict, list)):
                            content_str = json.dumps(
                                content, ensure_ascii=False, indent=2
                            )
                        else:
                            content_str = str(content)
                    else:
                        content_str = str(output)

                    print(f"Tool {block.name} succeeded: {repr(content_str[:100])}")

                    results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": content_str,
                        }
                    )

                except Exception as e:
                    # 捕获异常，将错误信息作为tool_result返回
                    import traceback

                    error_message = f"Tool call failed for '{block.name}':\n"
                    error_message += f"Error type: {type(e).__name__}\n"
                    error_message += f"Error message: {str(e)}\n"
                    error_message += "Full traceback:\n"
                    error_message += traceback.format_exc()

                    print(f"Tool {block.name} failed: {repr(str(e))}")

                    results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": error_message,
                            "is_error": True,  # 可选：添加错误标记
                        }
                    )
                if "update_todo_item" == block.name:
                    used_todo = True
                rounds_since_todo = 0 if used_todo else rounds_since_todo + 1
        # 将所有结果（包括成功和失败）添加到消息中
        messages.append({"role": "user", "content": results})


def main(user_request):

    init_tools_list()
    # print(TOOLS)
    # result = call_local_tool("launch_ida_instance", {"file_path": "C:\\Users\\user\\Desktop\\CcProtect.sys"})
    # print(result)
    history = []

    # 1. 用户请求
    # user_request = r"帮我分析一下Netfilter.sys是否存在BYOVD相关漏洞"
    # history.append({"role": "user", "content": user_request})
    history.append(
        {
            "role": "user",
            "content": [
                {"type": "text", "text": user_request},
                {
                    "type": "text",
                    "text": f"<system-reminder>Use the get_todo_list tool to retrieve your todo list.</system-reminder>",
                },
            ],
        }
    )
    agent_loop(history)
    # response_content = history[-1]["content"]

    # if isinstance(response_content, list):
    #     for block in response_content:
    #         if hasattr(block, "text"):
    #             print(block.text)

    # print(history)

if __name__=="__main__":

    main(r"帮我分析一下Netfilter.sys是否存在BYOVD相关漏洞") 
