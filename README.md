<div align="center">

<img src="assets/icon.png" width="112" alt="Code Security Review">

# Code Security Review

**粘贴代码即出安全审查报告，覆盖注入、鉴权与敏感数据泄露。**

[![License: MIT](https://img.shields.io/badge/license-MIT-0A3D91.svg)](LICENSE)
[![Skill Format](https://img.shields.io/badge/format-SKILL.md-FF9D1A.svg)](SKILL.md)
[![No Dependencies](https://img.shields.io/badge/dependencies-none-2B1470.svg)](#安装)
[![Defensive Use](https://img.shields.io/badge/use-defensive_only-0A3D91.svg)](SECURITY.md)

一个给 AI 编码助手用的**代码安全静态审查**技能。不写代码、不做渗透测试，只看一件事：这段代码会不会被打穿。

</div>

---

## 它解决什么问题

让 AI 看代码安不安全，通常得到两种结果：要么泛泛而谈「注意 SQL 注入」，要么一口气列二十条，真假混在一起分不清。

这个技能把审查拆成**固定三阶段**，每一类漏洞都有明确的「危险特征 / 合格特征 / 需进一步确认」判定标准，结论必须引用代码行作为证据。不确定的地方单独列进「待确认清单」，不混进漏洞统计。

**三个特点：**

- **有序**：先注入类，再认证授权，最后敏感数据。不跳步、不遗漏
- **有据**：每条结论都要指出文件和行号，没有证据的不下判断
- **可信**：区分「已确认」和「待确认」，总体风险等级只取已确认项的最高级

## 核心能力

| 阶段 | 覆盖范围 |
| --- | --- |
| 一、注入类 | SQL/NoSQL 注入、命令注入、XSS、SSRF、路径遍历、SSTI、LDAP/OGNL/ReDoS |
| 二、认证与授权 | 认证缺失与绕过、口令存储、会话管理、JWT、越权/IDOR、CSRF、权限校验缺失 |
| 三、敏感数据与加密 | 硬编码凭据、日志与错误泄露、传输安全、存储加密、过度收集、不安全反序列化 |
| 补充检查 | 文件上传、XXE、依赖供应链（需版本证据） |

判定统一走**数据流分析**：污染源（Source）→ 危险汇聚点（Sink）。用户输入未经有效净化抵达危险函数，且净化方式可被绕过，才判定为漏洞。

**定级标准**按可利用性 × 前置条件 × 影响范围 × 是否默认生效综合判断：

| 等级 | 名称 | 典型场景 |
| --- | --- | --- |
| P0 | 严重 | 未授权可达的 SQL 注入、命令注入、硬编码生产凭据 |
| P1 | 高危 | IDOR、存储型 XSS、SSRF、弱 JWT 密钥 |
| P2 | 中危 | 反射型 XSS、日志泄露敏感数据、CSRF |
| P3 | 低危 | 缺失安全响应头、版本信息泄露 |
| P4 | 提示 | 代码规范与最佳实践建议 |

## 安装

技能遵循通用 `SKILL.md` 格式，WorkBuddy、Claude Code、Trae 等支持该格式的客户端都能直接用。

**方式一：复制目录**（推荐，能带上全部判定标准）

```bash
git clone https://github.com/397814124my-wq/code-security-review.git

# WorkBuddy / Claude Code（用户级，所有项目可用）
cp -r code-security-review ~/.workbuddy/skills/
# 或 ~/.claude/skills/

# Trae（项目级）
cp -r code-security-review <your-project>/.trae/skills/
```

**方式二：仅用 SKILL.md**

复制 `SKILL.md` 到技能目录即可运行，但会失去 `references/` 里的判定标准库，结论稳定性会下降。**建议整个目录一起装。**

安装后不需要任何配置、密钥或网络服务，纯文本，离线可用。

## 使用

直接用自然语言提出请求，同时提供代码：

```
帮我审查这段代码安不安全
这个接口有没有漏洞
上线前帮我把把关
```

**输入**可以是粘贴的代码片段、单个文件、多文件，或者文件/目录路径。

**输出**固定六节 Markdown：

```
一、审查概览      语言框架、数据流摘要、总体风险等级、分项统计
二、漏洞清单      编号 / 位置 / 类型 / 等级 / 一句话结论 / 状态
三、漏洞详情      证据代码、数据流分析、影响、可直接粘贴的修复代码、CWE
四、待确认清单    缺什么信息、为什么判断不了、暂定等级与假设条件
五、修复优先级    P0 → P4 的修复顺序与理由
六、审查边界      静态审查范围声明
```

单条详情的形态：

> **V-01 SQL 注入 [严重 P0] [已确认]**
> - 位置：`orders_api.py:15-16`
> - 证据：`sql = "SELECT ... WHERE user_id = " + uid`
> - 分析：`uid` 从查询参数取得，未做类型转换即拼接进 SQL；该路由无鉴权装饰器
> - 影响：可读取全量订单含收货地址，可用 UNION 横向读取其他表
> - 修复：`uid = request.args.get("uid", type=int)` + `cur.execute("... WHERE user_id = %s", (uid,))`
> - 参考：CWE-89

## 命令行辅助（可选）

审查整个仓库时，可以用随附脚本先定位候选位置，再逐条人工复核：

```bash
python scripts/prescan.py <文件或目录>              # Markdown 输出
python scripts/prescan.py <目录> --json            # JSON 输出
python scripts/prescan.py <目录> --ext .py,.java   # 限定文件类型
```

零依赖，标准库实现，支持目录递归并自动跳过 `node_modules`、`.venv` 等依赖目录。

> **脚本只是定位线索，不作为结论。** 正则会产生误报，也会漏掉需要数据流分析才能发现的漏洞（如 IDOR、日志泄露 PII）。最终判定必须回到 `SKILL.md` 的判定流程。

## 演示案例

`examples/` 目录下有三份故意写坏的样本和对应报告，可以直接拿来试效果：

| 案例 | 栈 | 预置问题 |
| --- | --- | --- |
| [`examples/python-flask`](examples/python-flask/) | Python + Flask + SQLite | SQL 注入、硬编码密钥、IDOR、路径遍历、SSRF、日志泄露 |
| [`examples/java-spring`](examples/java-spring/) | Java + Spring Boot | SQL 注入、路径遍历、认证缺失、日志泄露 |
| [`examples/vue-frontend`](examples/vue-frontend/) | Vue 3 + Axios | 存储型 XSS、Token 存 localStorage、开放重定向 |

用法：打开任意样本文件，贴给助手并说「审查这段代码」。

## 它不做什么

写清楚边界，比夸大能力更有用：

| 不做 | 原因 |
| --- | --- |
| 不写新代码、不修 bug | 只审查，不改动 |
| 不做动态渗透、不发真实请求 | 静态审查，不运行代码 |
| 不做性能与架构评审 | 那是 code review 的范畴，不是安全审查 |
| 不保证 100% 检出 | 静态分析的固有局限，复杂业务逻辑漏洞可能漏判 |
| 不替代人工安全评审 | 高风险系统仍需专业渗透测试与代码审计 |

## 常见问题

**只粘贴代码不说用途，会开始审查吗？**

不会。它会先问你这段代码是做什么的，因为判断「ID 是否允许被猜」「接口是否本应公开」需要业务上下文。这类判断会标注 `[待确认-业务]`，并给出「若……则等级为……」的条件结论。

**为什么有些问题列在「待确认」而不是漏洞？**

缺调用方、框架版本或部署配置时，无法判断输入是否真的可控、漏洞是否真的生效。把猜测当结论会误导修复优先级，所以单独列出。

**审查结果和商业扫描器比如何？**

定位不同。商业引擎靠规则库和大规模样本，覆盖面更广；这个技能强在**能读懂业务语义**并给出可执行的修复代码，弱在无法做跨文件深度污点追踪。适合上线前自查和 code review 环节的补充。

**支持哪些语言？**

语言无关。`references/vulnerability-criteria.md` 内置了 Java、PHP、Python、Node.js、Go、C# 的高危 Sink API 对照表，其他语言按通用判定逻辑处理。

## 目录结构

```
code-security-review/
├── SKILL.md                          # 主流程：三阶段、判定标准、报告模板
├── references/
│   ├── vulnerability-criteria.md     # 判定特征库（危险/合格/待确认三态）
│   └── report-example.md             # 完整范例报告，对齐详略程度
├── scripts/
│   └── prescan.py                    # 可选：仓库级候选定位
├── examples/                         # 三份带漏洞的样本与报告
├── assets/                           # 图标
├── SECURITY.md                       # 防御性用途声明
└── LICENSE
```

## 授权

[MIT](LICENSE)。可自由使用、修改、分发，包括商业用途，保留版权声明即可。

## 关于

维护者：赵黎 · 公众号「产品三分钟」

如果这个技能帮你发现了真实问题，欢迎提 Issue 说说场景。发现漏判或误报，把代码片段贴进来，这比任何 star 都更有用。

---

<div align="center">
<sub>仅用于防御性安全审查。详见 <a href="SECURITY.md">SECURITY.md</a></sub>
</div>
