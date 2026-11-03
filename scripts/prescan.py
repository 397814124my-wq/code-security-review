#!/usr/bin/env python3
"""代码安全审查候选线索生成器（prescan）。

用途：在审查目录/仓库时快速定位高风险代码位置，输出「文件:行 + 规则 + 片段」候选清单。
定位原则：只做正则模式匹配，不理解数据流，因此**输出的每一条都必须人工复核**，
不得直接作为漏洞结论，也不得计入报告的漏洞统计。

用法：
    python prescan.py <path> [--ext .py,.js,.java] [--json] [--max-size 1048576]

输出：默认为 Markdown 表格，便于直接贴入审查过程；--json 输出结构化数据供后续处理。
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# 每行最多保留的字符数，避免超长压缩代码刷屏
SNIPPET_LIMIT = 160

# 跳过的目录（构建产物、依赖、版本库元数据）
SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "bower_components", "vendor",
    "__pycache__", ".venv", "venv", "env", "dist", "build", "target",
    "out", "bin", "obj", ".idea", ".vscode", "coverage", ".next", ".nuxt",
    "site-packages", "Pods", ".gradle", ".mvn",
}

# 常见源码后缀；未指定 --ext 时使用
DEFAULT_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".vue", ".java", ".kt", ".php",
    ".rb", ".go", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".scala",
    ".sh", ".bash", ".ps1", ".sql", ".xml", ".yml", ".yaml", ".properties",
    ".ini", ".conf", ".env", ".jsp", ".asp", ".aspx", ".tpl", ".ftl",
}

# 规则表：(规则ID, 分类, 正则, 等级提示, CWE)
# 等级提示为「若确认成立」的默认档位，实际定级需结合数据流与前置条件调整。
RULES = [
    # ---------- 硬编码凭据 ----------
    ("CRED-001", "硬编码凭据",
     r"""(?i)[A-Za-z0-9_]*(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|token|private[_-]?key)\s*[:=]\s*['"][^'"]{4,}['"]""",
     "P2", "CWE-798"),
    ("CRED-002", "私钥文件内容",
     r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
     "P0", "CWE-798"),
    ("CRED-003", "连接串内嵌口令",
     r"(?i)\b(?:jdbc:[a-z]+|mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp|smtp)://[^\s:@/'\"]+:[^\s:@/'\"]+@",
     "P0", "CWE-798"),

    # ---------- 注入类 ----------
    ("SQL-001", "SQL 语句拼接或插值",
     r"(?i)\b(select\b.{0,120}?\bfrom\b|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b).{0,120}?(\+\s*[A-Za-z_]\w*|\$\{|\{[A-Za-z_]\w*\}|%s?\s*%\s*\(|f[\"']|\.format\s*\()",
     "P1", "CWE-89"),
    ("SQL-002", "MyBatis ${} 拼接",
     r"(?i)\b(select|where|order\s+by|like)\b.{0,80}?\$\{[^}]+\}",
     "P1", "CWE-89"),
    ("SQL-003", "SQL 执行点（需回溯入参来源）",
     r"(?i)(\.execute(?:Query|Update)?\s*\(|\.rawQuery\s*\(|createQuery\s*\(|FromSqlRaw\s*\(|sequelize\.query\s*\(|\bdb\.Query\s*\()",
     "P3", "CWE-89"),
    ("CMD-001", "命令执行接口",
     r"(?i)\b(os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output|check_call)|commands\.getoutput|child_process\.(?:exec|execSync|spawnSync)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|shell_exec|passthru|proc_open|popen)\s*\(",
     "P1", "CWE-78"),
    ("CMD-002", "shell=True 调用",
     r"(?i)\bshell\s*=\s*True\b",
     "P1", "CWE-78"),
    ("CODE-001", "动态执行 / 表达式求值",
     r"(?i)(?<![\w.])(eval|exec|execfile|compile|create_function)\s*\(",
     "P2", "CWE-94"),
    ("DESER-001", "反序列化入口",
     r"(?i)(pickle\.loads?|cPickle\.loads?|yaml\.load\s*\(|marshal\.loads|joblib\.load|unserialize\s*\(|readObject\s*\(|ObjectInputStream|BinaryFormatter|XStream|enableDefaultTyping|autoType)",
     "P1", "CWE-502"),
    ("SSTI-001", "模板字符串渲染",
     r"(?i)(render_template_string|from_string\s*\(|Template\s*\(\s*(?!['\"])|\?interpret|ejs\.render\s*\(\s*(?!['\"]))",
     "P1", "CWE-1336"),
    ("LDAP-001", "LDAP 过滤器拼接",
     r"(?i)(search|filter)\s*[=(].*\b(uid|cn|mail)\s*=\s*[\"']?\s*(?:\+|%|\{|f[\"'])",
     "P2", "CWE-90"),
    ("REDOS-001", "嵌套量词正则（可能回溯爆炸）",
     r"\([^()]{0,40}[+*]\)[+*]|\(\.\*\)\{",
     "P3", "CWE-1333"),

    # ---------- XSS ----------
    ("XSS-001", "前端危险 HTML 写入",
     r"(innerHTML\s*=|outerHTML\s*=|dangerouslySetInnerHTML|v-html|document\.write\s*\(|insertAdjacentHTML\s*\()",
     "P1", "CWE-79"),
    ("XSS-002", "服务端取消转义",
     r"(?i)(\bMarkup\s*\(|\|\s*safe\b|Html\.Raw\s*\(|template\.HTML\s*\(|@Html\.Raw\s*\(|\bescape\s*\(\s*false|th:utext)",
     "P1", "CWE-79"),
    ("XSS-003", "字符串拼装 HTML",
     r"""(?i)(?:["'`]\s*<\s*(?:script|img|iframe|svg|a\s+href|div)\b[^"'`]*["'`]\s*\+)""",
     "P3", "CWE-79"),

    # ---------- 请求伪造与文件 ----------
    ("SSRF-001", "服务端请求外部 URL（入参需回溯）",
     r"(?i)(requests\.(?:get|post|put|head|request)\s*\(|urllib\.request\.urlopen\s*\(|axios\.(?:get|post)\s*\(|httpx\.(?:get|post)\s*\(|http\.Get\s*\(|curl_exec\s*\(|HttpClient\)?\.GetAsync\s*\(|RestTemplate)",
     "P2", "CWE-918"),
    ("PATH-001", "文件路径拼接",
     r"(?i)(?<![\w.])(open|readFile|readFileSync|writeFile|writeFileSync|createReadStream|FileInputStream|FileOutputStream|FileReader|fopen|file_get_contents|file_put_contents|os\.Open|os\.ReadFile|readFileSync)\s*\([^)\n]{0,120}?(\+|\$\{|\{[A-Za-z_]\w*\}|%s|\.format\s*\()",
     "P2", "CWE-22"),
    ("PATH-002", "路径拼接函数（需回溯入参）",
     r"(?i)(os\.path\.join\s*\(|(?<![.\w])path\.join\s*\(|filepath\.Join\s*\(|Paths\.get\s*\(|path\.resolve\s*\()",
     "P3", "CWE-22"),
    ("UPLOAD-001", "文件上传落盘",
     r"(?i)(move_uploaded_file\s*\(|\.transferTo\s*\(|\.save\s*\(\s*[a-z_]|CopyToAsync\s*\()",
     "P2", "CWE-434"),
    ("XXE-001", "XML 解析器初始化（需查是否禁用 DTD）",
     r"(?i)(DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLInputFactory\.newInstance|etree\.parse|libxml_disable_entity_loader|XMLReader\.Create)",
     "P3", "CWE-611"),

    # ---------- 认证 / 会话 / 传输 ----------
    ("JWT-001", "JWT 校验被关闭或算法未固定",
     r"(?i)(verify\s*=\s*False|jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify_signature['\"]?\s*:\s*False|algorithms\s*=\s*\[\s*['\"]none|['\"]alg['\"]\s*:\s*['\"]none)",
     "P1", "CWE-347"),
    ("CRYPTO-001", "弱哈希算法",
     r"(?i)\b(md5|sha1|des|rc4|blowfish)\b\s*\(",
     "P2", "CWE-327"),
    ("CRYPTO-002", "ECB 模式或弱算法常量",
     r"(?i)(AES/ECB|/ECB/|\bDES/|\bRC4\b|Cipher\.getInstance\s*\(\s*[\"']DES)",
     "P2", "CWE-327"),
    ("CRYPTO-003", "非密码学随机数",
     r"(?i)(Math\.random\s*\(\s*\)|random\.(?:random|randint|choice|randrange)\s*\(|\brand\s*\(\s*\))",
     "P3", "CWE-338"),
    ("TLS-001", "关闭证书校验",
     r"(?i)(verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|ServerCertificateValidationCallback)",
     "P2", "CWE-295"),
    ("CSRF-001", "CSRF 防护被显式关闭",
     r"(?i)(csrf_exempt|@csrf\.exempt|csrfProtection\s*=\s*false|\.disable\s*\(\s*\)\s*;?\s*//\s*csrf)",
     "P2", "CWE-352"),

    # ---------- 日志与错误 ----------
    ("LOG-001", "日志打印敏感字段",
     r"(?i)(log(?:ger)?|console|print|fmt\.Print|System\.out)[\w.]*\s*\(.{0,160}?(password|passwd|pwd|token|secret|credit_?card|id_?card|phone|mobile|authorization)",
     "P2", "CWE-532"),
    ("ERR-001", "生产环境调试或堆栈外泄",
     r"(?i)(debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|printStackTrace\s*\(\s*\)|show_stacktrace|display_errors\s*=\s*On)",
     "P2", "CWE-209"),
    ("CORS-001", "CORS 通配放行",
     r"(?i)(Access-Control-Allow-Origin['\"]?\s*[:=,]\s*['\"]\*|allow_origins\s*=\s*\[\s*['\"]\*|cors\s*\(\s*\)|origin\s*:\s*['\"]\*['\"])",
     "P2", "CWE-942"),
    ("TRUST-001", "信任客户端可伪造请求头",
     r"(?i)(x-forwarded-for|x-forwarded-host|x-original-url|x-rewrite-url)",
     "P3", "CWE-290"),
]


def compile_rules():
    """预编译规则；单条正则写错只跳过该条，不影响整体扫描。"""
    compiled = []
    for rule_id, category, pattern, level, cwe in RULES:
        try:
            compiled.append((rule_id, category, re.compile(pattern), level, cwe))
        except re.error as exc:  # pragma: no cover - 规则维护期保护
            print(f"[warn] 规则 {rule_id} 正则无效，已跳过：{exc}", file=sys.stderr)
    return compiled


COMPILED_RULES = compile_rules()


def iter_files(root: Path, exts):
    """遍历目标路径下的源码文件，跳过依赖目录与超大文件。"""
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            p = Path(dirpath) / name
            if exts and p.suffix.lower() not in exts:
                continue
            yield p


def scan_file(path: Path, max_size: int):
    """扫描单个文件，返回命中列表。"""
    hits = []
    try:
        if path.stat().st_size > max_size:
            return hits, "skipped:too-large"
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return hits, "skipped:unreadable"

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or len(stripped) > 4000:
            continue
        for rule_id, category, pattern, level, cwe in COMPILED_RULES:
            if pattern.search(line):
                snippet = stripped[:SNIPPET_LIMIT] + ("…" if len(stripped) > SNIPPET_LIMIT else "")
                hits.append({
                    "file": str(path),
                    "line": lineno,
                    "rule": rule_id,
                    "category": category,
                    "level_hint": level,
                    "cwe": cwe,
                    "code": snippet,
                })
    return hits, "ok"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description="代码安全审查候选线索生成器（结果需人工复核）")
    ap.add_argument("path", help="待扫描的文件或目录")
    ap.add_argument("--ext", default="", help="逗号分隔的扩展名过滤，如 .py,.js")
    ap.add_argument("--json", action="store_true", help="输出 JSON 而非 Markdown")
    ap.add_argument("--max-size", type=int, default=1024 * 1024, help="单文件大小上限（字节），默认 1MB")
    ap.add_argument("--limit", type=int, default=0, help="最多输出多少条命中，0 表示不限制")
    args = ap.parse_args()

    root = Path(args.path).expanduser()
    if not root.exists():
        print(f"路径不存在：{root}", file=sys.stderr)
        return 2

    exts = {e.strip().lower() for e in args.ext.split(",") if e.strip()} or DEFAULT_EXTS
    if root.is_file():
        exts = set()  # 显式指定单个文件时不做后缀过滤

    all_hits, scanned, skipped = [], 0, []
    for f in iter_files(root, exts):
        hits, status = scan_file(f, args.max_size)
        scanned += 1
        if status != "ok":
            skipped.append({"file": str(f), "reason": status})
        all_hits.extend(hits)

    if args.limit > 0:
        all_hits = all_hits[: args.limit]

    if args.json:
        print(json.dumps(
            {"root": str(root), "files_scanned": scanned, "hits": all_hits, "skipped": skipped},
            ensure_ascii=False, indent=2))
        return 0

    print("# 候选线索（prescan 自动生成，需逐条人工复核）\n")
    print(f"- 扫描范围：`{root}`")
    print(f"- 文件数：{scanned}　命中：{len(all_hits)}")
    if skipped:
        print(f"- 跳过：{len(skipped)} 个文件（过大或不可读）")
    print()

    if not all_hits:
        print("未命中任何规则。注意：无命中不等于无漏洞，规则库只覆盖常见模式。")
        return 0

    # 按分类汇总，便于按阶段安排复核顺序
    by_cat = {}
    for h in all_hits:
        by_cat.setdefault(h["category"], 0)
        by_cat[h["category"]] += 1
    print("## 分类汇总\n")
    for cat, n in sorted(by_cat.items(), key=lambda kv: -kv[1]):
        print(f"- {cat}：{n}")
    print()

    print("## 命中明细\n")
    print("| 文件:行 | 规则 | 分类 | 等级提示 | CWE | 代码片段 |")
    print("| --- | --- | --- | --- | --- | --- |")
    for h in all_hits:
        loc = f"{h['file']}:{h['line']}"
        code = h["code"].replace("|", "\\|")
        print(f"| `{loc}` | {h['rule']} | {h['category']} | {h['level_hint']} | {h['cwe']} | `{code}` |")

    print("\n> 以上为模式匹配结果，存在误报与漏报。确认漏洞必须回到数据流（Source → Sink）判断，"
          "并对照 references/vulnerability-criteria.md 逐条核实。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
