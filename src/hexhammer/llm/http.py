"""协议客户端共享的 HTTP 重试层:只重试瞬态错误,分类交给各协议实现。"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from .types import LLMError, LLMTransientError, RetryPolicy


def request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_payload: dict | None = None,
    classify: Callable[[int, str], LLMError],
    retry: RetryPolicy,
    sleep: Callable[[float], None],
) -> httpx.Response:
    """执行请求;非 2xx 或网络异常按 classify() 分类。

    - Transient:按退避重试至 retry.max_attempts,耗尽后抛最后一次错误;
    - Fatal / SessionDead:立即抛出不重试(变更安全原则同样适用于 LLM 层)。
    """
    last_error: LLMError | None = None
    for attempt in range(1, retry.max_attempts + 1):
        try:
            response = client.request(method, url, headers=headers, json=json_payload)
        except httpx.HTTPError as exc:  # 超时/连接/传输层
            last_error = LLMTransientError("network", str(exc))
        else:
            if response.status_code < 400:
                return response
            last_error = classify(response.status_code, response.text)
        assert last_error is not None
        if not isinstance(last_error, LLMTransientError):
            raise last_error
        if attempt == retry.max_attempts:
            raise last_error
        sleep(retry.delay_for(attempt))
    raise last_error  # pragma: no cover - 循环必经 return/raise
