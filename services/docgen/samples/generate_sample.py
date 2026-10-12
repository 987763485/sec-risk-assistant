#!/usr/bin/env python3
"""
生成 docgen 渲染接口的样例请求 JSON。

用途：
  1. P0 的最小渲染验证（scripts/verify-docgen.sh）
  2. 开发期手动调试：curl --data-binary @samples/sample-request.json ...

刻意构造了几类**最容易暴露 OpenXML 渲染缺陷**的内容：
  - 大量中文（验证字体名与编码）
  - 40 行表格，保证跨页（验证 w:tblHeader 表头跨页重复）
  - 横向合并单元格（验证 w:gridSpan）
  - 含连续空格与全角空格的文本（验证 xml:space="preserve"）
  - 中西文混排（验证 rFonts 的 Ascii / EastAsia 分别设置）

用法：
  python3 samples/generate_sample.py > samples/sample-request.json
"""

import json
import sys

# ─────────────────────────────────────────────────────────────── 表 1：判定标准
RISK_LEVELS = [
    ("很高", "R ≥ 20", "立即整改，阻断上线"),
    ("高",   "12 ≤ R < 20", "限期整改，纳入考核"),
    ("中",   "6 ≤ R < 12", "计划整改，跟踪验证"),
    ("低",   "2 ≤ R < 6", "持续关注，择机处理"),
    ("很低", "R < 2", "接受风险，记录备案"),
]

level_table = {
    "caption": "表 1　风险等级判定标准（阈值可在系统配置中调整）",
    "headers": ["风险等级", "风险值区间", "处置要求"],
    "rows": [list(row) for row in RISK_LEVELS],
    "repeatHeaderRow": True,
    # 在数据行之后补一行横跨全部 3 列的说明（验证 gridSpan 横向合并）
    "merges": [{"rowIndex": len(RISK_LEVELS), "startColumn": 0, "endColumn": 2,
                "text": "说明：风险值 R = 资产价值 × 威胁可能性 × 脆弱性严重度（GB/T 20984 相乘法）"}],
}
# 合并行也要有对应的行数据占位（渲染器会按 merge 覆盖其内容）
level_table["rows"].append(["", "", ""])

# ─────────────────────────────────────────────────────── 表 2：40 行风险矩阵
ASSETS = ["核心业务系统", "数据库服务器", "边界防火墙", "堡垒机", "日志审计系统",
          "VPN 网关", "邮件服务器", "DNS 服务", "文件服务器", "备份系统"]
THREATS = ["恶意代码", "越权访问", "口令爆破", "SQL 注入", "配置错误",
           "内部人员误操作", "供应链投毒", "拒绝服务", "数据泄露", "补丁缺失"]
VULNS = ["弱口令策略", "未启用双因素认证", "高危端口对外暴露", "过时组件版本",
         "日志留存不足", "备份未做恢复演练", "缺少最小权限划分", "明文传输"]

matrix_rows = []
for i in range(1, 41):
    asset = ASSETS[i % len(ASSETS)]
    threat = THREATS[i % len(THREATS)]
    vuln = VULNS[i % len(VULNS)]
    a, t, v = (i % 5) + 1, (i % 4) + 2, (i % 5) + 1
    r = a * t * v
    level = "很高" if r >= 20 else "高" if r >= 12 else "中" if r >= 6 else "低" if r >= 2 else "很低"
    matrix_rows.append([f"{i:02d}", asset, threat, vuln, str(a), str(t), str(v), str(r), level])

matrix_table = {
    "caption": "表 2　风险矩阵明细（共 40 项，跨页时表头应自动重复）",
    "headers": ["序号", "资产名称", "威胁", "脆弱性", "资产价值", "威胁可能性", "脆弱性严重度", "风险值", "等级"],
    "rows": matrix_rows,
    "repeatHeaderRow": True,
    "merges": [],
}

request = {
    "title": "示例信息系统网络安全风险评估报告",
    "subtitle": "评估依据：GB/T 20984《信息安全技术 信息安全风险评估方法》",
    "footerText": "内部资料　请勿外传",
    # 封面与目录：验证 P5 新增的三个可选字段（默认 false，老调用方不受影响）。
    # 封面把标题搬到第 1 页并插入分页符；目录生成一个 TOC 域，该域按大纲级别
    # 收集标题 —— 所以标题样式必须带 w:outlineLvl，否则更新域后目录全空且不报错。
    "coverPage": True,
    "tableOfContents": True,
    "sections": [
        {
            "heading": "一、评估概述",
            "level": 1,
            "paragraphs": [
                "本次评估以 GB/T 20984 相乘法为基本模型，从资产、威胁、脆弱性三个要素出发，"
                "对目标信息系统的安全风险进行量化分析，并给出分级结论与整改建议。",
                "评估范围覆盖核心业务系统、数据库、网络边界设备与安全审计设施，"
                "共采集资产 40 项，识别威胁 10 类、脆弱性 8 类。",
                "本文档由系统自动生成，用于验证报告渲染链路的中文排版、跨页表头与合并单元格能力。",
            ],
        },
        {
            "heading": "1.1 术语与缩略语",
            "level": 2,
            "paragraphs": [
                "风险值 R：资产价值 A、威胁可能性 T 与脆弱性严重度 V 三者的乘积，取值范围 1～125。",
                "　全角空格与  连续半角空格均应被保留（验证 xml:space=\"preserve\"）。",
            ],
        },
        {
            "heading": "二、风险等级判定标准",
            "level": 1,
            # 二级及以后的一级章节另起一页。第一节不设：目录之后本来就有
            # 分页符，再设一个会多出一整页空白。
            "pageBreakBefore": True,
            "paragraphs": [
                "依据系统配置中的阈值，将风险值映射为五级。阈值调整后本表会同步更新，无需修改模板。",
            ],
            "table": level_table,
        },
        {
            "heading": "三、风险矩阵明细",
            "level": 1,
            "pageBreakBefore": True,
            "paragraphs": ["下表列出全部 40 项资产的风险计算结果，按资产编号排序。"],
            "table": matrix_table,
        },
        {
            "heading": "四、整改建议",
            "level": 1,
            "pageBreakBefore": True,
            "paragraphs": [
                "针对「很高」与「高」等级风险，建议在 30 日内完成整改并复测；"
                "针对「中」等级风险，建议纳入季度安全计划；「低」及以下等级风险建议持续监控。",
                "整改完成后应重新执行评估，形成风险处置闭环。",
            ],
        },
    ],
}

json.dump(request, sys.stdout, ensure_ascii=False, indent=2)
sys.stdout.write("\n")
