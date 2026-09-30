---
name: weapon-research
description: >
  武器研发方法论(补丁差分研究链):CVE→情报→上游修复 commit 的 diff→根因
  →触发条件→PoC→本地靶验证→weapon save 入库。机械动作全走 weapon 工具
  (gh_search/readme/patch/save),研究判断你来做。铁律:半成品不入库;
  local-verified 必须有靶证据。
---

# 武器研发 — 从 CVE 到入库的可执行闭环

```
cve 工具(query=CVE-XXXX)          → 情报(影响版本/参考/PoC 仓库清单)
weapon gh_search(query=CVE-XXXX)   → PoC 仓库补充定位(星标排序)
weapon readme(repo=星标最高仓)     → README 常含:触发细节 + 上游修复 commit 链接
weapon patch(commit_url=上游修复)  → 统一 diff(研究核心材料)
        ↓ 你来分析(不外包):
根因 = 补丁改了什么防住什么(哪个检查/转义/边界被补上=漏洞本质)
触发 = 补丁前的输入路径 + 必要条件(版本/配置/权限)
PoC  = 最小可重放请求/命令(基于根因构造,不是抄 README——抄的也要能解释)
        ↓ 验证(cve-repro 技能的靶纪律):
vulhub/自搭受影响版本靶(127.0.0.1)→ PoC 打靶 → 拿到敏感输出
        ↓ 入库:
weapon save(cve/root_cause/trigger/poc/verified=local-verified/evidence=靶输出摘录)
```

## 分析纪律

1. **diff 优先于 README 结论**:README 的"vulnerability"描述常有偏差;
   diff 里的 hunk 位置就是漏洞位置——先自己从 diff 读出根因再对照;
2. **触发条件三问**:哪个版本区间?需要什么前置(认证/配置/路由)?边界
   条件是什么(路径格式/编码/次数)?答不齐不算研究完成;
3. **PoC 最小化**:能证明根因即可(读一个文件/回显一个标记),不追求
   影响最大化——武器库里放的是"可解释的利用件",不是黑盒魔法串;
4. 验证失败(靶打不通)时:先复核版本是否在受影响区间,再复核触发条件,
   最后才怀疑根因;证伪也是结论,如实记 unverified+原因。

## 入库标准(weapon save)

- cve/root_cause/trigger/poc 四件缺一不可;
- `local-verified` 必须 evidence=靶上的真实输出摘录;
- 已有同 CVE 条目幂等跳过(想更新走人工编辑库文件)。
