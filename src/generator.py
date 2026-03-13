import json
import os
from datetime import datetime, timezone, timedelta

def format_number(num):
    """为数字添加千位分隔符，例如：1234567 -> 1,234,567"""
    return f"{num:,}" if isinstance(num, int) else "0"

def main():
    print("📝 开始执行自动化 README 渲染引擎...")
    
    # 1. 检查必要文件是否存在
    if not os.path.exists("rules/stats.json"):
        print("❌ 致命错误：未找到 rules/stats.json！请确保 builder.py 成功运行。")
        exit(1)
    if not os.path.exists("README_template.md"):
        print("❌ 致命错误：未找到 README_template.md 模板文件！")
        exit(1)
        
    # 2. 读取核心引擎产出的统计数据
    with open("rules/stats.json", "r", encoding="utf-8") as f:
        stats = json.load(f)
        
    # 3. 获取标准北京时间 (UTC+8)
    tz_utc_8 = timezone(timedelta(hours=8))
    update_time = datetime.now(tz_utc_8).strftime("%Y-%m-%d %H:%M:%S (UTC+8)")
    
    # 4. 兼容性提取分类数据
    types_data = stats.get("types", {})
    if not types_data:
        types_data = stats # 如果未嵌套在 types 里，直接从外层取
        
    # 5. 构建渲染数据字典 (Data Context)
    render_data = {
        "update_time": update_time,
        "lite_total": format_number(stats.get("lite_total", 0)),
        "full_total": format_number(stats.get("full_total", 0)),
        "extreme_total": format_number(stats.get("extreme_total", 0)),
        "conflicts_resolved": format_number(stats.get("conflicts_resolved", 0)),
        "failed_sources": format_number(stats.get("failed_sources", 0)),
        "ad_count": format_number(types_data.get("ad", 0)),
        "tracking_count": format_number(types_data.get("tracking", 0)),
        "malicious_count": format_number(types_data.get("malicious", 0)),
        "allow_count": format_number(types_data.get("allow", 0))
    }
    
    # 6. 读取模板文件
    with open("README_template.md", "r", encoding="utf-8") as f:
        template = f.read()
        
    # 7. 执行模板渲染注入
    try:
        # format_map 可以用字典里的键值对安全地替换字符串里的 {变量}
        readme_content = template.format_map(render_data)
    except KeyError as e:
        print(f"❌ 模板渲染失败：README_template.md 中包含了未提供的数据变量 {e}")
        exit(1)
        
    # 8. 写入最终展示的 README.md
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)
        
    print(f"✅ README.md 渲染彻底完成！")
    print(f"   📊 本次注入数据: 极限版规则 {render_data['extreme_total']} 条, 解决冲突 {render_data['conflicts_resolved']} 次。")

if __name__ == "__main__":
    main()
