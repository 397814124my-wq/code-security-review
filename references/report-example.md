# 报告范例（格式对齐用）

下面是一份完整示例，仅用于对齐结构、详略与措辞。实际审查时按真实代码重写，禁止复用其中的漏洞结论。

输入：一段 Flask 用户查询接口。

```python
@app.route("/api/user")
def get_user():
    uid = request.args.get("id")
    db = pymysql.connect(host="10.0.0.5", user="root", password="Passw0rd@2023")
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + uid)
    rows = cur.fetchall()
    app.logger.info("query %s -> %s", uid, rows)
    return jsonify(rows)
```

---

## 一、审查概览

- 审查对象：Python 3 / Flask / 用户信息查询接口（`get_user`）
- 数据流摘要：`request.args['id']` → 字符串拼接 → `cursor.execute` 执行；`rows` → 应用日志
- 总体风险等级：严重（P0）
- 统计：严重 2 / 高危 0 / 中危 1 / 低危 0 / 提示 0 / 待确认 1

## 二、漏洞清单（总表）

| 编号 | 位置（文件:行） | 漏洞类型 | 等级 | 一句话结论 | 状态 |
| --- | --- | --- | --- | --- | --- |
| V-01 | app.py:4-6 | SQL 注入 | 严重 | 请求参数直接拼接进 SQL 并执行，可读取任意表 | 已确认 |
| V-02 | app.py:3 | 硬编码凭据 | 严重 | 数据库 root 口令明文写死在源码中 | 已确认 |
| V-03 | app.py:7 | 日志敏感信息泄露 | 中危 | 完整用户记录写入应用日志，包含 PII | 已确认 |

## 三、漏洞详情

### V-01 SQL 注入 [严重 P0] [已确认]

- **位置**：app.py:6
- **证据**：

```python
uid = request.args.get("id")
cur.execute("SELECT * FROM users WHERE id = " + uid)
```

- **分析**：`id` 直接取自 query string，未做类型转换，通过 `+` 拼接进 SQL 语句后执行。攻击者传入 `1 OR 1=1` 即可返回整表，传入 `1 UNION SELECT ...` 可跨库读取。该接口无鉴权装饰器，未授权可达，因此定级为严重。
- **影响**：可读取 `users` 表全部字段（含口令哈希、手机号），并可借 `UNION` 读取同库其他业务表，造成全量数据泄露。
- **修复建议**：

```python
@app.route("/api/user")
@login_required                      # 补充鉴权，见 V-03 备注
def get_user():
    uid = request.args.get("id", type=int)   # 强制类型转换
    if uid is None:
        abort(400, "invalid id")
    with get_db() as conn:                    # 连接由连接池提供，见 V-02
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, email FROM users WHERE id = %s", (uid,))
            row = cur.fetchone()
    return jsonify(row)
```

要点：占位符 `%s` 由驱动做参数绑定，不做字符串拼接；同时把 `SELECT *` 改为显式字段，避免敏感列外泄。

- **参考**：CWE-89

### V-02 硬编码凭据 [严重 P0] [已确认]

- **位置**：app.py:3
- **证据**：

```python
db = pymysql.connect(host="10.0.0.5", user="root", password="Passw0rd@2023")
```

- **分析**：数据库 root 账号口令以明文常量形式存在于源码中，随代码仓库、构建产物、日志、异常栈多条路径扩散。使用 root 账号连接进一步放大了凭据泄露后的影响面。
- **影响**：任何能读取仓库或制品的人可直接连接生产库（10.0.0.5），获得读写权限；凭据一旦进入 git 历史，删除代码也无法回收。
- **修复建议**：

```python
import os

DB_CONFIG = {
    "host": os.environ["DB_HOST"],
    "user": os.environ["DB_USER"],          # 使用最小权限业务账号，非 root
    "password": os.environ["DB_PASSWORD"],  # 由 KMS/Vault 注入
    "database": os.environ["DB_NAME"],
}
```

配套动作：将该口令在数据库侧立即轮换，并清理 git 历史中的该字符串；生产环境改用密钥管理服务下发。

- **参考**：CWE-798

### V-03 日志敏感信息泄露 [中危 P2] [已确认]

- **位置**：app.py:7
- **证据**：

```python
app.logger.info("query %s -> %s", uid, rows)
```

- **分析**：`rows` 为完整用户记录，直接进入 info 级日志。日志通常集中采集、长期留存、访问控制弱于数据库，等于在另一个位置复制了一份敏感数据。
- **影响**：手机号、邮箱、口令哈希等字段落入日志平台，任何具备日志查看权限的运维、开发、外包人员均可获取，且难以追溯。
- **修复建议**：

```python
app.logger.info("query user id=%s hits=%d", uid, len(rows))   # 只记标识与数量
```

- **参考**：CWE-532

## 四、待确认清单

| 编号 | 问题描述 | 原因类型 | 需要的补充信息 | 暂定等级与假设 |
| --- | --- | --- | --- | --- |
| Q-01 | 该接口是否需要登录才能访问 | 上下文不足 | 路由注册处的全局鉴权中间件、网关 ACL 配置 | 若完全公开则 V-01 维持 P0；若已有网关鉴权则降为 P1 |

## 五、修复优先级

1. **V-02 硬编码凭据**（P0）：先轮换口令，再改配置注入。凭据已泄露，仅改代码不轮换等于未修。
2. **V-01 SQL 注入**（P0）：改参数化查询并补鉴权，两者需同批上线。
3. **V-03 日志泄露**（P2）：低成本改动，可与上批合并发布。
4. **Q-01 鉴权确认**：补齐信息后回填结论，影响 V-01 的最终定级。

## 六、审查边界

- 静态审查，未运行代码；动态验证（实际注入 payload）不在本次范围
- 未提供 `requirements.txt`，pymysql 与 Flask 版本未知，供应链风险未评估
- 结论仅针对所提供片段，不延伸推断其他路由的安全性

一句话总结：该接口未鉴权、以 root 明文口令连接数据库并将用户参数拼接进 SQL，构成可直接利用的严重注入与凭据泄露风险，须先轮换凭据再改参数化查询。
