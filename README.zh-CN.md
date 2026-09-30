# hexhammer

自主渗透测试引擎。给它一个授权目标,它自己完成从侦察到取证的完整渗透链;给它一个 CVE 编号,它自己拉补丁、分析根因、构造 PoC、搭靶验证。

**[English](README.md)** | 简体中文

## 它能做什么

**自主渗透测试**

```
授权目标 → 侦察 → 漏洞利用 → 拿到立足点 → 提权 → 内网横向 → 取证报告
```

引擎自主决策每一步:识别服务指纹、选择攻击路径、构造 payload、分析结果、调整策略。全程留痕,产出结构化漏洞报告(可重放的请求/响应证据)。

**漏洞复现与武器研发**

```
CVE 编号 → 拉上游补丁 diff → 根因分析 → 构造 PoC → 本地靶验证 → 入库
```

从补丁差分反推漏洞本质,自动化 1day 武器化流程。

**攻防一体(攻守闭环)**

```
渗透 → 漏洞报告 + 修复建议 → 你修复 → 同款引擎复测 → 验证修复生效
```

不只是找漏洞,还能验证修复。

**交互对话**

```bash
hexhammer chat
```

你说一句,它做一步。丢一个 URL、一段代码、一个 CVE 编号,它围绕你给的内容自主分析。流式输出,工具调用实时可见。

## 六维能力

| 维度 | 覆盖 |
|---|---|
| Web 漏洞挖掘 | openapi 枚举、越权/注入/XSS/SSRF 探测、WAF 绕过 |
| 多阶段渗透 | 立足→提权→横向→域攻,AD 域配方链(Kerberos/ADCS/ACL/中继) |
| 二进制 | checksec、反汇编、ROP、栈溢出利用 |
| 云攻击 | SSRF→云元数据→凭据获取、桶探测、本机凭证枚举 |
| 对抗规避 | WAF 过滤分析、编码绕过、载体变换 |
| 漏洞利用 | CVE 情报聚合、补丁差分、PoC 构造、靶验证 |

## 安装

```bash
# 克隆
git clone https://github.com/Aimer-zero/hexhammer.git && cd hexhammer

# 安装依赖(需要 Python 3.10+)
uv sync

# 配置 LLM
cp .env.example .env
# 编辑 .env,填入你的 API key(支持 OpenAI 兼容网关/deepseek/Anthropic)

# 检查外部工具依赖(缺失不阻塞)
uv run hexhammer doctor
```

## 使用

### 自主渗透(一键)

```bash
# 侦察画像(只读)
uv run hexhammer scan --target <授权IP> --mode recon

# Web/API 渗透
uv run hexhammer scan --target <授权IP> --mode webapp

# 完整链 + RCE 证明(取证后自动复原)
uv run hexhammer scan --target <授权IP> --mode chain --authorize-rce-proof
```

**授权档位**(默认只读,按需升级):
- 默认:只读探测 + 无害验证
- `--authorize-rce-proof`:允许命令执行取证(id/echo 级,不落盘,证完复原)
- 交互模式下可通过 `/target` 动态切换目标

### 交互对话

```bash
uv run hexhammer chat
```

命令:`exit` 退出 / `clear` 清会话 / `/target <ip>` 切换目标

### 经验审阅(学习线人审门)

引擎每次 mission 后自动蒸馏经验条目,人工审批后入库,下次自动注入:

```bash
uv run hexhammer review <mission目录>                   # 查看待审
uv run hexhammer review <mission目录> --approve-all     # 批准入库
```

### 产物

每次 scan 产出:
- `notes.md`:全过程 + 结论
- `flags.json`:漏洞清单(可重放证据)
- `timeline.jsonl`:每步留痕
- `cost.json`:token 消耗

## 工具面(20 件)

| 类别 | 工具 |
|---|---|
| 文件系统 | read / write / edit / grep / find / ls |
| Shell | bash(守卫封装) |
| HTTP | http(结构化请求+留痕)/ bypass403(变体枚举) |
| 编码 | encode(base64/hex/url/html/rot13/unicode 链式) |
| 侦察 | nmap(守卫封装)/ osint(四源被动) |
| 注入 | sqlmap(守卫封装)/ jwt(decode/crack/forge) |
| 云 | cloud(元数据/凭证/桶) |
| 二进制 | binary(checksec/symbols/disasm/gadgets) |
| 武器 | cve(情报聚合)/ weapon(补丁 diff/PoC 入库) |
| 审计 | audit(sink 扫描/调用链)/ hypothesis(假设树) |
| 交付 | finding(漏洞落账)/ loot(战利品) |

## 成本

deepseek-chat 档:单轮 mission 约 ¥0.5~2(cache 命中 90%+)。

## 项目结构

```
src/hexhammer/
├── solver/          agent 循环(工具调用+再驱动+压缩)
├── control/         编排(两阶段+PassClock 预算+断点恢复)
├── tools/           20 件工具
├── run/             CLI 入口(scan/chat/doctor/review)
├── experience.py    经验库(蒸馏→人审→注入)
├── observer.py      外环观察者(覆盖图蒸馏)
├── playbooks.py     域知识装配(6 域 playbook + 7 技能)
└── eval/            本地 A/B 测试套件

resources/
├── playbooks/       六域攻击手册(web/pentest/binary/cloud/evasion/exploit)
├── skills/          方法论技能(waf-bypass/ssrf-chain/cve-repro/weapon-research 等)
└── experience/      经验库(实弹蒸馏,人审入库)
```

## ⚠️ 风险与责任

**本项目仅供安全研究和授权渗透测试使用。**

- **你必须拥有目标的书面授权**才能对其进行测试
- 未经授权的渗透测试在大多数司法管辖区属于**刑事犯罪**
- 引擎的探测行为可能触发目标方的安全防护(IP 封禁/告警/法律追究)
- 引擎产出的漏洞报告可能包含敏感信息,请妥善保管
- **使用者承担全部法律责任,本项目开发者不承担任何因滥用导致的后果。**

**最佳实践:**
- 只对自己拥有的资产或获得明确书面授权的资产使用
- 在隔离环境中测试(本地靶场/专用测试网段)
- 妥善保管 `.env` 中的 API key(已 gitignore)
- 定期检查引擎产出,确认无误报后才提交给相关方

## License

Apache-2.0
