# 审查报告 · Python Flask 订单接口

> 样本：`orders_api.py`（6 个路由，Flask + SQLite + PyJWT）
> 本报告由 Code Security Review 生成，用于演示输出形态。

## 一、审查概览

- **审查对象**：Python 3 / Flask / SQLite / PyJWT
- **数据流摘要**：`request.args`、`request.get_json()` → SQL 拼接、文件路径拼接、外部 HTTP 请求、日志输出
- **总体风险等级**：**P0 严重**
- **统计**：严重 2 / 高危 3 / 中危 1 / 低危 0 / 提示 0 / 待确认 1

## 二、漏洞清单

| 编号 | 位置 | 漏洞类型 | 等级 | 结论 | 状态 |
| --- | --- | --- | --- | --- | --- |
| V-01 | orders_api.py:14-18 | SQL 注入 | P0 严重 | `uid` 直接拼进 SQL，可拖库 | 已确认 |
| V-02 | orders_api.py:8,45 | 硬编码密钥 | P0 严重 | JWT 密钥写死在源码，可伪造任意身份 | 已确认 |
| V-03 | orders_api.py:21-24 | 越权 IDOR | P1 高危 | 按 `oid` 取单，无归属校验 | 已确认 |
| V-04 | orders_api.py:27-31 | 路径遍历 | P1 高危 | `file` 未规范化，可读任意文件 | 已确认 |
| V-05 | orders_api.py:34-38 | SSRF | P1 高危 | `url` 任意可控，且关闭证书校验 | 已确认 |
| V-06 | orders_api.py:17 | 日志泄露 PII | P2 中危 | 完整结果集写入日志，含收货地址 | 已确认 |
| Q-01 | 全局 | 认证缺失 | 待确认 | 路由无鉴权装饰器，是否由网关统一拦截 | 待确认 |

## 三、漏洞详情

### V-01 SQL 注入 [P0 严重] [已确认]

- **位置**：`orders_api.py:14-18`
- **证据**：

```python
uid = request.args.get("uid")
sql = "SELECT id, amount, address FROM orders WHERE user_id = " + uid
rows = app.config["DB"].execute(sql).fetchall()
```

- **分析**：`uid` 取自查询参数，未做类型转换即字符串拼接。`execute()` 收到完整 SQL 文本，无参数绑定。污染源直达危险汇聚点，无任何净化环节。
- **影响**：可读取全量订单（含收货地址），通过 `UNION` 横向读取用户表、凭据表。若数据库账号权限较高，可进一步写入文件。
- **修复**：

```python
uid = request.args.get("uid", type=int)
if uid is None:
    return jsonify(error="invalid uid"), 400
rows = app.config["DB"].execute(
    "SELECT id, amount, address FROM orders WHERE user_id = ?", (uid,)
).fetchall()
```

- **参考**：CWE-89

### V-02 硬编码 JWT 密钥 [P0 严重] [已确认]

- **位置**：`orders_api.py:8`、`:45`
- **证据**：

```python
JWT_SECRET = "mhm_secret_2023"
token = jwt.encode({"uid": data["uid"]}, JWT_SECRET, algorithm="HS256")
```

- **分析**：签名密钥以明文常量写在源码中。任何拿到源码或镜像的人都能离线签发合法 token。同时 `jwt.encode` 只写入 `uid`，未设 `exp`，令牌永不过期。
- **影响**：攻击者可伪造任意 `uid` 的身份，完全绕过登录。配合 V-03 可遍历全部订单。
- **修复**：

```python
import os, time
JWT_SECRET = os.environ["JWT_SECRET"]          # 从密钥管理注入，禁止写入源码

payload = {"uid": user_id, "exp": int(time.time()) + 3600}
token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
```

- **参考**：CWE-798、CWE-613

### V-03 越权 IDOR [P1 高危] [已确认]

- **位置**：`orders_api.py:21-24`
- **证据**：

```python
@app.route("/api/order/<oid>")
def get_order(oid):
    order = app.config["DB"].execute("SELECT * FROM orders WHERE id = %s", (oid,)).fetchone()
    return jsonify(order)
```

- **分析**：查询用了参数绑定，SQL 层面安全。但只按 `id` 取数据，**没有任何归属校验**——不检查该订单是否属于当前登录用户。`oid` 为自增整数，可枚举。
- **影响**：遍历 `oid` 即可拖走全部用户订单，含金额与收货地址。
- **修复**：

```python
@app.route("/api/order/<int:oid>")
@login_required
def get_order(oid):
    order = app.config["DB"].execute(
        "SELECT * FROM orders WHERE id = ? AND user_id = ?", (oid, current_user.id)
    ).fetchone()
    if order is None:
        return jsonify(error="not found"), 404
    return jsonify(order)
```

- **参考**：CWE-639

## 四、待确认清单

| 编号 | 问题 | 原因类型 | 需要补充的信息 | 暂定等级与假设 |
| --- | --- | --- | --- | --- |
| Q-01 | 6 个路由均无鉴权装饰器，是否由网关或中间件统一拦截 | 上下文不足 | 部署架构、网关配置、是否有全局 `before_request` | 若无需认证即可访问，V-01/V-03 提升为未授权可利用；若网关已拦截，两处降为越权 |

## 五、修复优先级

1. **V-02** 换密钥 + 加 `exp`——成本最低，收益最大，先堵伪造入口
2. **V-01** 参数化查询——一条 SQL 注入等于全部数据失守
3. **V-03** 加归属校验——需要引入登录态，工作量略大
4. **V-04 / V-05** 路径规范化、URL 白名单、恢复证书校验
5. **V-06** 日志脱敏——不影响功能，随时可改

## 六、审查边界

静态审查，未运行代码。结论仅针对 `orders_api.py` 所提供片段，不推断未展示的模型层与网关配置。依赖版本未提供，供应链风险未评估。
