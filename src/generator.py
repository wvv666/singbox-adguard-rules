import json
import os
from datetime import datetime, timezone, timedelta

def generate_readme():
    print("📝 开始生成动态 README 数据面板...")
    
    stats_file = 'rules/stats.json'
    template_file = 'src/templates/README_template.md'
    output_file = 'README.md'
    
    # 1. 安全检查：确保所需文件存在
    if not os.path.exists(stats_file):
        print(f"❌ 找不到统计文件: {stats_file}。请确保先运行了 builder.py！")
        return
    if not os.path.exists(template_file):
        print(f"❌ 找不到模板文件: {template_file}。")
        return

    # 2. 读取数据和模板
    with open(stats_file, 'r', encoding='utf-8') as f:
        stats = json.load(f)

    with open(template_file, 'r', encoding='utf-8') as f:
        readme_content = f.read()

    # 3. 获取当前时间并转换为东八区 (北京/台北时间)
    utc_now = datetime.now(timezone.utc)
    cst_tz = timezone(timedelta(hours=8))
    cst_now = utc_now.astimezone(cst_tz)
    update_time_str = cst_now.strftime("%Y-%m-%d %H:%M:%S")

    # 4. 准备替换字典 (利用 :, 实现千分位格式化，例如 15000 变成 15,000)
    replacements = {
        "{{ UPDATE_TIME }}": update_time_str,
        "{{ CONFLICTS_RESOLVED }}": f"{stats.get('conflicts_resolved', 0):,}",
        "{{ LITE_TOTAL }}": f"{stats.get('lite_total', 0):,}",
        "{{ FULL_TOTAL }}": f"{stats.get('full_total', 0):,}",
        "{{ EXTREME_TOTAL }}": f"{stats.get('extreme_total', 0):,}"
    }

    # 5. 循环执行文本替换
    for placeholder, actual_value in replacements.items():
        readme_content = readme_content.replace(placeholder, str(actual_value))

    # 6. 将最终内容写入根目录的 README.md
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(readme_content)
        
    print(f"✅ README.md 生成成功！")
    print(f"📊 最新数据 - Lite: {replacements['{{ LITE_TOTAL }}']} | Full: {replacements['{{ FULL_TOTAL }}']} | Extreme: {replacements['{{ EXTREME_TOTAL }}']}")

if __name__ == '__main__':
    generate_readme()
