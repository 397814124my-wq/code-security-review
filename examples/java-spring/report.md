# 审查报告 · Java Spring 订单控制器

> 样本：`OrderController.java`（4 个端点，Spring Boot + JdbcTemplate）
> 本报告由 Code Security Review 生成，用于演示输出形态。

## 一、审查概览

- **审查对象**：Java 17 / Spring Boot / JdbcTemplate
- **数据流摘要**：`@RequestParam`、`@PathVariable`、`@RequestBody` → SQL 拼接、文件路径拼接、日志输出
- **总体风险等级**：**P0 严重**
- **统计**：严重 3 / 高危 1 / 中危 1 / 低危 0 / 提示 0 / 待确认 1

## 二、漏洞清单

| 编号 | 位置 | 漏洞类型 | 等级 | 结论 | 状态 |
| --- | --- | --- | --- | --- | --- |
| V-01 | OrderController.java:35-38 | SQL 注入 | P0 严重 | `uid` 拼进 SQL，`queryForList` 直接执行 | 已确认 |
| V-02 | OrderController.java:32,60 | 硬编码凭据 | P0 严重 | 管理员令牌写在常量里 | 已确认 |
| V-03 | OrderController.java:46-49 | 认证缺失 + 越权 | P0 严重 | 退款接口无鉴权、无归属校验、无金额校验 | 已确认 |
| V-04 | OrderController.java:41-44 | 路径遍历 | P1 高危 | `name` 未规范化，可逃逸出目录 | 已确认 |
| V-05 | OrderController.java:53 | 日志泄露 | P2 中危 | 整个请求体写入日志，含令牌 | 已确认 |
| Q-01 | 全局 | 认证机制 | 待确认 | 是否有 Spring Security 过滤器链统一拦截 | 待确认 |

## 三、漏洞详情

### V-01 SQL 注入 [P0 严重] [已确认]

- **位置**：`OrderController.java:35-38`
- **证据**：

```java
@GetMapping("/orders")
public List<Map<String, Object>> listOrders(@RequestParam String uid) {
    String sql = "SELECT id, amount, address FROM orders WHERE user_id = " + uid;
    return jdbc.queryForList(sql);
}
```

- **分析**：`uid` 声明为 `String`，未做类型约束即字符串拼接。`JdbcTemplate.queryForList(String)` 接收的是完整 SQL 文本，属于原生查询重载，不走预编译。污染源直达汇聚点。
- **影响**：可拖库。`queryForList` 返回 `Map` 列表，列名与值全部回显给调用方，数据泄露面最广的一种形态。
- **修复**：

```java
@GetMapping("/orders")
public List<Map<String, Object>> listOrders(@RequestParam("uid") Long uid) {
    return jdbc.queryForList(
        "SELECT id, amount, address FROM orders WHERE user_id = ?", uid);
}
```

若 `uid` 必须为字符串，改用 `queryForList(sql, new Object[]{uid})` 的参数形式，并额外做白名单校验。

- **参考**：CWE-89

### V-02 硬编码凭据 [P0 严重] [已确认]

- **位置**：`OrderController.java:32`、`:60`
- **证据**：

```java
private static final String ADMIN_TOKEN = "admin-8f3a9c21d4e7b0a5";
...
if (ADMIN_TOKEN.equals(body.get("token"))) { return "granted"; }
```

- **分析**：管理员令牌以常量形式编译进 class 文件。即使源码不公开，反编译 jar 即可取得明文。且为静态令牌，无法轮换、无法追溯使用者。
- **影响**：任何人拿到构建产物即可获得管理员权限，且无法通过改密码止损——只能重新发布版本。
- **修复**：

```java
// 从配置中心/环境变量注入，并改用不可逆哈希比对
@Value("${admin.token.hash}")
private String adminTokenHash;

if (passwordEncoder.matches(body.get("token"), adminTokenHash)) {
    return "granted";
}
```

更彻底的做法是取消静态管理员令牌，改为基于角色的账号体系。

- **参考**：CWE-798

### V-03 认证缺失与越权 [P0 严重] [已确认]

- **位置**：`OrderController.java:46-49`
- **证据**：

```java
@PostMapping("/orders/{id}/refund")
public String refund(@PathVariable Long id, @RequestParam int amount) {
    jdbc.update("UPDATE orders SET refunded = ? WHERE id = ?", amount, id);
    return "ok";
}
```

- **分析**：SQL 用了参数绑定，注入层面安全。但存在三个叠加问题：① 端点无任何认证注解，也未做权限判断；② `id` 由调用方指定，不校验订单归属；③ `amount` 未校验是否超过原订单金额。三者叠加构成直接的资损路径。
- **影响**：未授权者遍历 `id` 调用即可批量退款，`amount` 可任意设置（含大于订单金额），属于可造成实际资金损失的越权。
- **修复**：

```java
@PostMapping("/orders/{id}/refund")
@PreAuthorize("hasRole('ADMIN')")
public String refund(@PathVariable Long id,
                     @RequestParam @Min(1) int amount,
                     @AuthenticationPrincipal User user) {
    Order order = orderRepo.findByIdAndUserId(id, user.getId())
        .orElseThrow(() -> new NotFoundException());
    if (amount > order.getAmount()) {
        throw new IllegalArgumentException("amount exceeds order total");
    }
    order.refund(amount);
    return "ok";
}
```

- **参考**：CWE-306、CWE-639、CWE-840

## 四、待确认清单

| 编号 | 问题 | 原因类型 | 需要补充的信息 | 暂定等级与假设 |
| --- | --- | --- | --- | --- |
| Q-01 | 是否配置了 Spring Security 全局过滤器链 | 上下文不足 | `SecurityFilterChain` 配置、`application.yml` | 若已全局拦截 `/api/**` 并要求认证，V-03 降为「越权」仍需修归属校验；若未配置，维持 P0 |

## 五、修复优先级

1. **V-03** 退款接口——唯一能直接造成资金损失的入口，立即下线或加鉴权
2. **V-02** 令牌改注入 + 哈希，并规划轮换
3. **V-01** 参数化查询
4. **V-04** 路径规范化后校验前缀
5. **V-05** 日志改为不记录请求体，或对 `token` 字段脱敏

## 六、审查边界

静态审查，未运行代码。仅针对所提供 `OrderController.java`，未涉及实体定义、Repository 实现与安全配置。依赖版本未知，未评估 Spring 框架自身 CVE。
