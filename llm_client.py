"""
Universal LLM client — supports OpenAI-compatible and Anthropic native APIs.
Pure stdlib, no external dependencies.

Usage:
    from llm_client import LLMConfig, chat_stream, chat

    config = LLMConfig(api_key="sk-...", base_url="https://api.openai.com", model="gpt-4o")
    for chunk in chat_stream(config, system="You are helpful", user="Hello"):
        print(chunk, end="", flush=True)
"""

import json
import ssl
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Generator


@dataclass
class LLMConfig:
    api_key: str
    base_url: str
    model: str
    provider: str = ""      # "openai" | "anthropic" — auto-detected if empty
    max_tokens: int = 8192
    temperature: float = 0.3
    timeout: int = 300      # seconds

    def __post_init__(self):
        if not self.provider:
            self.provider = self._detect_provider()
        # Normalize base_url
        self.base_url = self.base_url.rstrip("/")

    def _detect_provider(self) -> str:
        if "anthropic" in self.base_url or self.model.startswith("claude"):
            return "anthropic"
        return "openai"


def _estimate_tokens(text: str) -> int:
    """Rough token estimate for mixed Chinese/English text."""
    return int(len(text) / 3.5)


def _create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    return ctx


def _do_request(req: urllib.request.Request, timeout: int) -> urllib.response.HTTPResponse:
    """Execute request with retry on 429/5xx."""
    last_err = None
    for attempt in range(3):
        try:
            ctx = _create_ssl_context()
            return urllib.request.urlopen(req, timeout=timeout, context=ctx)
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429 or e.code >= 500:
                wait = 2 ** attempt * 2
                time.sleep(wait)
                continue
            raise
        except urllib.error.URLError as e:
            last_err = e
            if attempt < 2:
                time.sleep(2 ** attempt * 2)
                continue
            raise
    raise last_err


def _parse_sse_lines(lines: list[str]) -> Generator[str, None, None]:
    """Parse SSE lines and yield content deltas."""
    for line in lines:
        line = line.strip()
        if not line or line.startswith(":"):
            continue
        if line.startswith("data: "):
            data = line[6:]
            if data == "[DONE]":
                return
            try:
                obj = json.loads(data)
                yield obj
            except json.JSONDecodeError:
                continue


def chat_stream(config: LLMConfig, system: str, user: str) -> Generator[str, None, None]:
    """Stream LLM response. Yields text chunks."""
    est_in = _estimate_tokens(system + user)
    est_out = config.max_tokens
    print(f"  [LLM] estimated input: ~{est_in} tokens, max output: {est_out} tokens", flush=True)

    if config.provider == "anthropic":
        yield from _stream_anthropic(config, system, user)
    else:
        yield from _stream_openai(config, system, user)


def chat(config: LLMConfig, system: str, user: str) -> str:
    """Non-streaming call. Returns full response."""
    chunks = []
    # For non-streaming, use non-stream endpoint
    if config.provider == "anthropic":
        return _call_anthropic(config, system, user)
    else:
        return _call_openai(config, system, user)


def _build_openai_payload(config: LLMConfig, system: str, user: str, stream: bool) -> bytes:
    body = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": config.max_tokens,
        "temperature": config.temperature,
        "stream": stream,
    }
    return json.dumps(body).encode("utf-8")


def _stream_openai(config: LLMConfig, system: str, user: str) -> Generator[str, None, None]:
    url = f"{config.base_url}/v1/chat/completions"
    payload = _build_openai_payload(config, system, user, stream=True)
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.api_key}",
        },
    )
    resp = _do_request(req, config.timeout)
    buffer = ""
    for chunk in iter(lambda: resp.read(4096), b""):
        buffer += chunk.decode("utf-8", errors="replace")
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            for obj in _parse_sse_lines([line]):
                delta = obj.get("choices", [{}])[0].get("delta", {})
                content = delta.get("content", "")
                if content:
                    yield content


def _call_openai(config: LLMConfig, system: str, user: str) -> str:
    url = f"{config.base_url}/v1/chat/completions"
    payload = _build_openai_payload(config, system, user, stream=False)
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.api_key}",
        },
    )
    resp = _do_request(req, config.timeout)
    data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


def _build_anthropic_payload(config: LLMConfig, system: str, user: str, stream: bool) -> bytes:
    body = {
        "model": config.model,
        "max_tokens": config.max_tokens,
        "temperature": config.temperature,
        "system": system,
        "messages": [
            {"role": "user", "content": user},
        ],
        "stream": stream,
    }
    return json.dumps(body).encode("utf-8")


def _stream_anthropic(config: LLMConfig, system: str, user: str) -> Generator[str, None, None]:
    url = f"{config.base_url}/v1/messages"
    payload = _build_anthropic_payload(config, system, user, stream=True)
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "x-api-key": config.api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    resp = _do_request(req, config.timeout)
    buffer = ""
    for chunk in iter(lambda: resp.read(4096), b""):
        buffer += chunk.decode("utf-8", errors="replace")
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.strip()
            if not line or line.startswith(":"):
                continue
            if line.startswith("data: "):
                data = line[6:]
                try:
                    obj = json.loads(data)
                    if obj.get("type") == "content_block_delta":
                        text = obj.get("delta", {}).get("text", "")
                        if text:
                            yield text
                except json.JSONDecodeError:
                    continue


def _call_anthropic(config: LLMConfig, system: str, user: str) -> str:
    url = f"{config.base_url}/v1/messages"
    payload = _build_anthropic_payload(config, system, user, stream=False)
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "x-api-key": config.api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    resp = _do_request(req, config.timeout)
    data = json.loads(resp.read().decode("utf-8"))
    return data["content"][0]["text"]
