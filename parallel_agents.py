# parallel_agents.py
import concurrent.futures
import threading
from agent import main  # 导入您已有的agent主函数
import time

# 提示词模板 - 将驱动路径嵌入分析请求
PROMPT_TEMPLATE = "请帮我分析一下{driver_path}是否存在BYOVD相关漏洞"

def run_agent_for_driver(driver_path):
    """
    为单个驱动文件运行agent分析
    """
    thread_name = threading.current_thread().name
    print(f"[{thread_name}] 开始分析驱动: {driver_path}")
    
    try:
        # 使用模板生成具体的分析请求
        user_request = PROMPT_TEMPLATE.format(driver_path=driver_path)
        
        # 记录开始时间
        start_time = time.time()
        
        # 调用agent的主分析函数
        main(user_request)
        
        # 计算耗时
        elapsed_time = time.time() - start_time
        print(f"[{thread_name}] 完成分析: {driver_path} (耗时: {elapsed_time:.2f}秒)")
        
        return {"driver": driver_path, "status": "success", "time": elapsed_time}
        
    except Exception as e:
        print(f"[{thread_name}] 分析失败 {driver_path}: {e}")
        return {"driver": driver_path, "status": "failed", "error": str(e)}

def parallel_run_agents(driver_paths, max_workers=3):
    """
    并行运行多个agent分析不同的驱动文件
    
    参数:
    - driver_paths: 驱动文件路径列表
    - max_workers: 最大并行数，默认为3
    """
    print(f"开始并行分析 {len(driver_paths)} 个驱动文件")
    print(f"最大并行数: {max_workers}")
    print("-" * 50)
    
    results = []
    
    # 使用ThreadPoolExecutor实现并行执行
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_driver = {
            executor.submit(run_agent_for_driver, path): path 
            for path in driver_paths
        }
        
        # 收集结果
        for future in concurrent.futures.as_completed(future_to_driver):
            driver_path = future_to_driver[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"任务异常 {driver_path}: {e}")
                results.append({"driver": driver_path, "status": "exception", "error": str(e)})
    
    # 输出汇总报告
    print("\n" + "=" * 50)
    print("分析任务汇总:")
    print("=" * 50)
    
    success_count = sum(1 for r in results if r.get("status") == "success")
    failed_count = sum(1 for r in results if r.get("status") == "failed")
    exception_count = sum(1 for r in results if r.get("status") == "exception")
    
    print(f"成功: {success_count} 个")
    print(f"失败: {failed_count} 个")
    print(f"异常: {exception_count} 个")
    
    # 显示详细信息
    if failed_count > 0 or exception_count > 0:
        print("\n详细结果:")
        for result in results:
            status = result.get("status", "unknown")
            driver = result.get("driver", "unknown")
            if status == "success":
                print(f"  ✓ {driver}: 成功 (耗时: {result.get('time', 0):.2f}秒)")
            elif status == "failed":
                print(f"  ✗ {driver}: 失败 - {result.get('error', '未知错误')}")
            elif status == "exception":
                print(f"  ⚠ {driver}: 异常 - {result.get('error', '未知异常')}")
    
    return results

if __name__ == "__main__":
    # 示例用法 - 替换为您的实际驱动文件路径
    driver_files = [
        r"C:\Users\user\Desktop\BYOVD\BdApiUtil64.sys",
        r"C:\Users\user\Desktop\BYOVD\CcProtect.sys",
        r"C:\Users\user\Desktop\BYOVD\K7RKScan_1516.sys",
        r"C:\Users\user\Desktop\BYOVD\K7RKScan_2310.sys",
        r"C:\Users\user\Desktop\BYOVD\ksapi64.sys",
        r"C:\Users\user\Desktop\BYOVD\ksapi64_del.sys",
        r"C:\Users\user\Desktop\BYOVD\NSecKrnl.sys",
        r"C:\Users\user\Desktop\BYOVD\STProcessMonitor_v114.sys",
        r"C:\Users\user\Desktop\BYOVD\STProcessMonitor_v2618.sys",
        r"C:\Users\user\Desktop\BYOVD\SysMon.sys",
        r"C:\Users\user\Desktop\BYOVD\viragt64.sys",
        r"C:\Users\user\Desktop\BYOVD\wsftprm.sys",
    ]
    
    # 并行运行agent分析
    results = parallel_run_agents(driver_files, max_workers=2)