"""云攻击工具面:元数据 / 凭证 / 桶探测——云维度与 SSRF 链的结构化入口。

知识来源:resources/skills/ssrf-chain(SSRF 打云元数据的完整链路)的
机械部分代码化。三条动作:

- metadata:链路本地元数据端点探测(AWS IMDSv1/v2、Aliyun、GCP),命中即
  输出身份指纹(角色名/实例 ID;凭证只给存在性+前缀,不回吐完整密钥);
- creds:本机已知凭证位置只读枚举(~/.aws、env、kubeconfig、SA token 等),
  值一律脱敏(前 6 位 + 长度)——云题第一步与容器逃逸后的标准动作;
- bucket:对象存储公开性判定(ListBucketResult=可列;AccessDenied=存在私有;
  NoSuchBucket/DNS 解析失败=不存在),S3/OSS/COS 同判定逻辑。

输出纪律:凭证值永不全文回显(它是证据不是弹药,拿去用最小化)。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import ClassVar

import httpx

from .attack import _request
from .base import ToolContext, ToolError

# 已知凭证位置(只读枚举):路径 → 说明
_CRED_LOCATIONS = (
    (".aws/credentials", "AWS CLI 凭证"),
    (".aws/config", "AWS CLI 配置"),
    (".aliyun/config.json", "Aliyun CLI 凭证"),
    (".config/gcloud/credentials.db", "GCP 凭证库"),
    (".config/gcloud/legacy_credentials", "GCP 旧凭证目录"),
    (".kube/config", "kubeconfig(集群凭证)"),
    (".docker/config.json", "registry 凭证"),
    (".netrc", "netrc 明文凭证"),
    (".ssh/id_rsa", "SSH 私钥"),
    (".terraform.d", "terraform 状态/凭证"),
)
_CRED_ENV_KEYS = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
    "TF_VAR_aws_secret_key", "GITHUB_TOKEN",
)
# 容器内常见挂载(K8s SA / Docker socket / 云 runtime)
_RUNTIME_LOCATIONS = (
    ("/var/run/secrets/kubernetes.io/serviceaccount/token", "K8s ServiceAccount token"),
    ("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "K8s CA"),
    ("/var/run/docker.sock", "Docker socket(可枚举/逃逸)"),
    ("/var/run/crio/crio.sock", "CRI-O socket"),
    ("/etc/kubernetes/admin.conf", "集群 admin 凭证"),
    ("/host/run/secrets/kubernetes.io/serviceaccount/token", "宿主 SA token 挂载"),
)

_METADATA_ENDPOINTS = (
    ("aws-v1", "http://169.254.169.254/latest/meta-data/", {}),
    ("aliyun", "http://100.100.100.100/latest/meta-data/", {}),
    ("gcp", "http://metadata.google.internal/computeMetadata/v1/instance/",
     {"Metadata-Flavor": "Google"}),
)

# 凭证值脱敏:前 6 + 长度
def _mask(value: str) -> str:
    return f"{value[:6]}…(len={len(value)})" if len(value) > 6 else f"(len={len(value)})"


class CloudTool:
    name = "cloud"
    description = (
        "Cloud attack surface toolkit. metadata: probe link-local metadata "
        "endpoints (AWS IMDSv1/v2, Aliyun, GCP) — SSRF-to-credential chain step 1. "
        "creds: read-only enumerate local credential locations (files/env/runtime "
        "mounts), values masked. bucket: object-storage exposure check "
        "(S3/OSS/COS: listable vs private vs missing)."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["metadata", "creds", "bucket"]},
            "url": {"type": "string", "description": "bucket: full URL to probe"},
            "home": {"type": "string", "description": "creds: home dir override"},
        },
        "required": ["action"],
    }

    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def execute(self, args: dict, ctx: ToolContext) -> str:
        action = args["action"]
        if action == "metadata":
            return self._metadata(args)
        if action == "creds":
            return self._creds(args)
        if action == "bucket":
            return self._bucket(args)
        raise ToolError(f"unknown action {action!r}")

    # ---- 元数据探测

    def _metadata(self, args: dict) -> str:
        lines = ["# 元数据端点探测(链路本地,3s 超时快速失败)"]
        for name, url, headers in _METADATA_ENDPOINTS:
            try:
                status, _, body = _request(
                    "GET", url, headers=headers, timeout=3.0,
                    transport=self._transport,
                )
            except ToolError as exc:
                lines.append(f"## {name}: 不可达({str(exc)[:60]})")
                continue
            if status != 200:
                lines.append(f"## {name}: HTTP {status}(端点在但拒绝)")
                continue
            root = "\n".join(body.strip().splitlines()[:15])
            lines.append(f"## {name}: 开放!")
            lines.append(f"根路径内容:\n{root}")
        # AWS v2 检查:能拿 token 说明 v2 启用(v1 可能仍开——降级漏洞特征)
        try:
            status, _, body = _request(
                "PUT", "http://169.254.169.254/latest/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                timeout=3.0, transport=self._transport,
            )
            if status == 200 and body.strip():
                lines.append(
                    f"## AWS IMDSv2:token 可获取(启用);v1 若同时开放=降级漏洞"
                    f"(token={_mask(body.strip())})"
                )
        except ToolError:
            pass
        if not any("开放" in ln for ln in lines):
            lines.append("结论:本机/本容器视界内无云元数据(非云环境或已加固)")
        lines.append("下一步:命中 AWS → iam/security-credentials/ 拿角色凭证名;"
                     "GCP → ?recursive=true;完整链路见 ssrf-chain 技能。")
        return "\n".join(lines)

    # ---- 本机凭证枚举(只读,值脱敏)

    def _creds(self, args: dict) -> str:
        home = Path(args.get("home") or Path.home())
        lines = [f"# 本机凭证枚举(只读;home={home})"]
        hits = 0
        for rel, label in _CRED_LOCATIONS:
            path = home / rel
            if path.exists():
                hits += 1
                size = path.stat().st_size if path.is_file() else -1
                lines.append(f"## {label}:存在 {rel}" + (f"({size}B)" if size >= 0 else "(目录)"))
        for abs_path, label in _RUNTIME_LOCATIONS:
            if Path(abs_path).exists():
                hits += 1
                lines.append(f"## {label}:存在 {abs_path}")
        env_hits = [
            k for k in _CRED_ENV_KEYS if os.environ.get(k)
        ]
        for key in env_hits:
            hits += 1
            lines.append(f"## env {key}={_mask(os.environ[key])}")
        if not hits:
            lines.append("无命中(裸环境)。")
        lines.append("纪律:凭证是证据——记录、最小化使用,不大段复制进报告。")
        return "\n".join(lines)

    # ---- 桶公开性

    def _bucket(self, args: dict) -> str:
        url = str(args.get("url") or "").strip()
        if not url:
            raise ToolError("bucket 需要 url(桶完整 URL,如 https://<name>.oss-cn-hangzhou.aliyuncs.com/)")
        try:
            status, _, body = _request(
                "GET", url, timeout=8.0, transport=self._transport,
            )
        except ToolError as exc:
            return f"{url}\n不可达/DNS 无解析({str(exc)[:80]})→ 桶大概率不存在"
        lowered = body[:400].lower()
        if status == 200 and "listbucketresult" in lowered:
            names = "\n".join(body.strip().splitlines()[:20])
            return f"{url}\n公开可列(ListBucketResult,HTTP 200)!\n{names}"
        if status == 403 or "accessdenied" in lowered:
            return f"{url}\n存在但私有(HTTP {status}/AccessDenied)——攻击面收敛,可试列举绕过(版本后缀/?list-type=2&prefix=)"
        if "nosuchbucket" in lowered or status == 404:
            return f"{url}\n不存在(NoSuchBucket/404)"
        return f"{url}\nHTTP {status},非典型响应:\n{body[:300]}"
