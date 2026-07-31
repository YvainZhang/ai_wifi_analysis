"""
Universal LLM client — supports OpenAI-compatible and Anthropic native APIs.
Pure stdlib, no external dependencies.

Usage:
    from llm_client import LLMConfig, chat_stream, chat

    config = LLMConfig(api_key="sk-...", base_url="https://api.openai.com", model="gpt-4o")
    for chunk in chat_stream(config, system="You are helpful", user="Hello"):
        print(chunk, end="", flush=True)
"""

import codecs
import http.client
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Generator, Iterator


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


def _do_request(req: urllib.request.Request, timeout: int) -> http.client.HTTPResponse:
    """Execute request with retry on 429/5xx."""
    last_err = None
    for attempt in range(3):
        try:
            ctx = _create_ssl_context()
            return urllib.request.urlopen(req, timeout=timeout, context=ctx)
        except urllib.error.HTTPError as e:
            last_err = e
            if (e.code == 429 or e.code >= 500) and attempt < 2:
                e.close()
                wait = 2 ** attempt * 2
                time.sleep(wait)
                continue
            e.close()
            raise
        except urllib.error.URLError as e:
            last_err = e
            if attempt < 2:
                time.sleep(2 ** attempt * 2)
                continue
            raise
    raise last_err


def _api_url(base_url: str, endpoint: str) -> str:
    """Join an API base URL and a versioned endpoint without duplicating /v1."""
    versioned_base = base_url if base_url.endswith("/v1") else f"{base_url}/v1"
    return f"{versioned_base}/{endpoint.lstrip('/')}"


def _iter_utf8_lines(resp: http.client.HTTPResponse) -> Iterator[str]:
    """Yield complete UTF-8 lines from a byte stream, including the EOF tail."""
    decoder = codecs.getincrementaldecoder("utf-8")()
    buffer = ""

    while True:
        chunk = resp.read(4096)
        if not chunk:
            buffer += decoder.decode(b"", final=True)
            break

        buffer += decoder.decode(chunk)
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            yield line.rstrip("\r")

    if buffer:
        yield buffer.rstrip("\r")


_SSE_DONE = object()


def _parse_sse_data(data: str) -> Any:
    """Decode one SSE data field as JSON, or return the stream-end sentinel."""
    if data.strip() == "[DONE]":
        return _SSE_DONE
    try:
        obj = json.loads(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid SSE JSON payload: {e.msg}") from e
    if not isinstance(obj, dict):
        raise ValueError("Invalid SSE JSON payload: expected an object")
    return obj


def _iter_sse_json(resp: http.client.HTTPResponse) -> Iterator[dict]:
    """Parse an SSE byte stream and yield JSON objects from data fields."""
    data_lines = []

    for line in _iter_utf8_lines(resp):
        if not line:
            if not data_lines:
                continue
            obj = _parse_sse_data("\n".join(data_lines))
            data_lines = []
            if obj is _SSE_DONE:
                return
            yield obj
            continue

        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            data = line[5:]
            if data.startswith(" "):
                data = data[1:]
            data_lines.append(data)
            # Provider streams normally terminate each event with a blank
            # line, but some compatible servers emit one complete JSON
            # object per data line without the separator.
            try:
                obj = _parse_sse_data("\n".join(data_lines))
            except ValueError:
                continue
            data_lines = []
            if obj is _SSE_DONE:
                return
            yield obj

    if data_lines:
        obj = _parse_sse_data("\n".join(data_lines))
        if obj is not _SSE_DONE:
            yield obj


def _raise_stream_error(obj: dict, provider: str) -> None:
    """Raise a useful exception for provider error events."""
    if "error" not in obj and obj.get("type") != "error":
        return

    error = obj.get("error")
    if isinstance(error, dict):
        message = error.get("message") or error.get("type") or json.dumps(error)
    elif error:
        message = str(error)
    else:
        message = "unknown streaming error"
    raise RuntimeError(f"{provider} API stream error: {message}")


def chat_stream(config: LLMConfig, system: str, user: str) -> Generator[str, None, None]:
    """Stream LLM response. Yields text chunks."""
    est_in = _estimate_tokens(system + user)
    est_out = config.max_tokens
    print(
        f"  [LLM] estimated input: ~{est_in} tokens, max output: {est_out} tokens",
        file=sys.stderr,
        flush=True,
    )

    if config.provider == "anthropic":
        yield from _stream_anthropic(config, system, user)
    else:
        yield from _stream_openai(config, system, user)


def chat(config: LLMConfig, system: str, user: str) -> str:
    """Non-streaming call. Returns full response."""
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
    url = _api_url(config.base_url, "chat/completions")
    payload = _build_openai_payload(config, system, user, stream=True)
    headers = {
        "Content-Type": "application/json",
    }
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers=headers,
    )
    resp = _do_request(req, config.timeout)
    try:
        for obj in _iter_sse_json(resp):
            _raise_stream_error(obj, "OpenAI")
            choices = obj.get("choices")
            if not isinstance(choices, list) or not choices:
                continue
            choice = choices[0]
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta", {})
            if not isinstance(delta, dict):
                continue
            content = delta.get("content", "")
            if isinstance(content, str) and content:
                yield content
    finally:
        resp.close()


def _call_openai(config: LLMConfig, system: str, user: str) -> str:
    url = _api_url(config.base_url, "chat/completions")
    payload = _build_openai_payload(config, system, user, stream=False)
    headers = {"Content-Type": "application/json"}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers=headers,
    )
    resp = _do_request(req, config.timeout)
    try:
        data = json.loads(resp.read().decode("utf-8"))
    finally:
        resp.close()
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
    url = _api_url(config.base_url, "messages")
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
    try:
        for obj in _iter_sse_json(resp):
            _raise_stream_error(obj, "Anthropic")
            if obj.get("type") != "content_block_delta":
                continue
            delta = obj.get("delta", {})
            if not isinstance(delta, dict):
                continue
            text = delta.get("text", "")
            if isinstance(text, str) and text:
                yield text
    finally:
        resp.close()


def _call_anthropic(config: LLMConfig, system: str, user: str) -> str:
    url = _api_url(config.base_url, "messages")
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
    try:
        data = json.loads(resp.read().decode("utf-8"))
    finally:
        resp.close()
    return data["content"][0]["text"]
