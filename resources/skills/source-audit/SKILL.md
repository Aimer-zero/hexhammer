---
name: source-audit
description: >
  源码审计方法论(从代码到漏洞):audit 工具 sinks 扫描危险调用 → trace
  回溯入口 → 判断数据流可控性 → 构造触发验证。适用于 Python/PHP/Java
  等语言的快速审计。
---

# 源码审计 — 从 sink 到可利用漏洞

```
audit sinks(path=源码目录)
  → 危险调用清单(cmd-exec/sql-inject/path-traversal/deserialization/ssrf/…)
  ↓ 筛选:高价值 sink(入口可控+中间无过滤)
audit trace(path, symbol=sink 所在函数)
  → 调用链:入口(路由/CLI)→ 中间 → sink
  ↓ 判读:
  入口是用户输入(HTTP 参数/文件上传/CLI 参数)?
  中间有无过滤/转义/白名单?
  ↓ 构造触发:
  根据数据流从入口注入恶意输入(最小化:证明可控即可)
  ↓ 验证:本地/远程靶上 PoC 打通
```

## sink 优先级(按利用价值)

| 类别 | 价值 | 说明 |
|---|---|---|
| cmd-exec | ★★★ | 直接 RCE |
| deserialization | ★★★ | 反序列化 RCE(有 gadget chain) |
| sql-inject | ★★ | 数据外带/认证绕过(取决于后端) |
| ssrf | ★★ | 内网穿透/云元数据(取决于网络位置) |
| path-traversal | ★★ | 任意文件读(信息泄露/LFI→RCE 链) |
| xss-ssti | ★ | 需要受害者交互/模板引擎 |
| hardcoded-secret | ★ | 凭证泄露(间接利用) |

## 判读规则

1. **入口可控 + 无过滤 = 高价值**:从 HTTP 参数/上传文件直达 sink,
   中间无 sanitize/validate → 立即构造 PoC;
2. **入口可控 + 有过滤**:分析过滤的完备性(编码绕过/类型混淆/逻辑
   分支遗漏)——这正好是 evasion 方法论的用武之地;
3. **非入口(内部调用/定时任务)**:检查间接可达性(注入内部数据源);
4. **闭源/编译型**:换 binary 工具(checksec/disasm/strings)做
   二进制审计,方法论同构。

## 与补丁差分的关系

- 补丁差分(weapon-research):已知漏洞 → 反推根因 → PoC(逆向);
- 源码审计:主动发现未知漏洞(正向);
- 两者互补:审计发现的疑似漏洞若上游已修复,diff 可加速根因确认。
