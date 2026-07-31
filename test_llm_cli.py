import io
import json
import subprocess
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

import llm_client
import wifi_analyzer


class FakeResponse:
    def __init__(self, chunks):
        self._chunks = iter(chunks)
        self.closed = False

    def read(self, _size=-1):
        return next(self._chunks, b"")

    def close(self):
        self.closed = True


def openai_event(content):
    return json.dumps(
        {"choices": [{"delta": {"content": content}}]},
        ensure_ascii=False,
    )


class SSEStreamTest(unittest.TestCase):
    def setUp(self):
        self.openai_config = llm_client.LLMConfig(
            api_key="test-key",
            base_url="https://example.test/v1/",
            model="test-model",
            provider="openai",
        )
        self.anthropic_config = llm_client.LLMConfig(
            api_key="test-key",
            base_url="https://example.test/v1",
            model="test-model",
            provider="anthropic",
        )

    def test_openai_stream_preserves_split_utf8_and_eof_tail(self):
        event = ("data:" + openai_event("中文")).encode("utf-8")
        split_at = event.index("中".encode("utf-8")) + 1
        response = FakeResponse([event[:split_at], event[split_at:]])
        requested_urls = []

        def fake_request(req, _timeout):
            requested_urls.append(req.full_url)
            return response

        with patch.object(llm_client, "_do_request", side_effect=fake_request):
            output = "".join(
                llm_client._stream_openai(self.openai_config, "system", "user")
            )

        self.assertEqual(output, "中文")
        self.assertEqual(
            requested_urls,
            ["https://example.test/v1/chat/completions"],
        )
        self.assertTrue(response.closed)

    def test_openai_stream_handles_empty_choices_and_done(self):
        payload = (
            'data: {"choices": []}\n'
            f"data: {openai_event('before')}\n"
            "data:[DONE]\n"
            f"data: {openai_event('after')}\n\n"
        ).encode("utf-8")
        response = FakeResponse([payload])

        with patch.object(llm_client, "_do_request", return_value=response):
            output = "".join(
                llm_client._stream_openai(self.openai_config, "system", "user")
            )

        self.assertEqual(output, "before")
        self.assertTrue(response.closed)

    def test_openai_stream_raises_provider_error_and_closes(self):
        response = FakeResponse(
            [b'data: {"error":{"message":"quota exhausted"}}\n\n']
        )

        with patch.object(llm_client, "_do_request", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "OpenAI.*quota exhausted"):
                list(llm_client._stream_openai(
                    self.openai_config, "system", "user"
                ))

        self.assertTrue(response.closed)

    def test_closing_stream_generator_closes_response(self):
        payload = (
            f"data: {openai_event('first')}\n\n"
            f"data: {openai_event('second')}\n\n"
        ).encode("utf-8")
        response = FakeResponse([payload])

        with patch.object(llm_client, "_do_request", return_value=response):
            stream = llm_client._stream_openai(
                self.openai_config, "system", "user"
            )
            self.assertEqual(next(stream), "first")
            self.assertFalse(response.closed)
            stream.close()

        self.assertTrue(response.closed)

    def test_anthropic_stream_raises_provider_error_and_closes(self):
        response = FakeResponse([
            b"event: error\n"
            b'data:{"type":"error","error":'
            b'{"type":"overloaded_error","message":"try later"}}\n\n'
        ])

        with patch.object(llm_client, "_do_request", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "Anthropic.*try later"):
                list(llm_client._stream_anthropic(
                    self.anthropic_config, "system", "user"
                ))

        self.assertTrue(response.closed)

    def test_invalid_sse_json_raises_and_closes(self):
        response = FakeResponse([b"data: {invalid}\n\n"])

        with patch.object(llm_client, "_do_request", return_value=response):
            with self.assertRaisesRegex(ValueError, "Invalid SSE JSON"):
                list(llm_client._stream_openai(
                    self.openai_config, "system", "user"
                ))

        self.assertTrue(response.closed)

    def test_non_streaming_response_is_closed(self):
        body = json.dumps({
            "choices": [{"message": {"content": "complete"}}],
        }).encode("utf-8")
        response = FakeResponse([body])

        with patch.object(llm_client, "_do_request", return_value=response):
            output = llm_client._call_openai(
                self.openai_config, "system", "user"
            )

        self.assertEqual(output, "complete")
        self.assertTrue(response.closed)


class RequestBehaviorTest(unittest.TestCase):
    def test_last_retryable_http_error_does_not_sleep(self):
        errors = []

        def fail_request(*_args, **_kwargs):
            error = urllib.error.HTTPError(
                "https://example.test",
                500,
                "server error",
                {},
                io.BytesIO(b""),
            )
            errors.append(error)
            raise error

        request = urllib.request.Request("https://example.test")
        with (
            patch.object(
                llm_client.urllib.request,
                "urlopen",
                side_effect=fail_request,
            ) as urlopen,
            patch.object(llm_client.time, "sleep") as sleep,
        ):
            with self.assertRaises(urllib.error.HTTPError):
                llm_client._do_request(request, timeout=1)

        self.assertEqual(urlopen.call_count, 3)
        self.assertEqual(sleep.call_args_list, [call(2), call(4)])
        self.assertTrue(all(error.closed for error in errors))

    def test_non_retryable_http_error_is_closed(self):
        error = urllib.error.HTTPError(
            "https://example.test",
            401,
            "unauthorized",
            {},
            io.BytesIO(b""),
        )
        request = urllib.request.Request("https://example.test")

        with patch.object(
                llm_client.urllib.request,
                "urlopen",
                side_effect=error,
        ):
            with self.assertRaises(urllib.error.HTTPError):
                llm_client._do_request(request, timeout=1)

        self.assertTrue(error.closed)

    def test_api_url_accepts_root_or_v1_base(self):
        self.assertEqual(
            llm_client._api_url(
                "https://api.example.test",
                "chat/completions",
            ),
            "https://api.example.test/v1/chat/completions",
        )
        self.assertEqual(
            llm_client._api_url(
                "https://api.example.test/v1",
                "chat/completions",
            ),
            "https://api.example.test/v1/chat/completions",
        )


class WifiAnalyzerCLITest(unittest.TestCase):
    def setUp(self):
        self.result = {
            "meta": {
                "total_packets": 1,
                "duration": 0.1,
            },
        }
        self.config = SimpleNamespace(
            api_key="test-key",
            provider="openai",
            model="test-model",
            base_url="https://example.test",
            max_tokens=10,
        )

    def test_ai_path_adds_problem_description_only_in_prompt(self):
        generate_report = patch.object(
            wifi_analyzer,
            "generate_report",
            return_value="extracted data",
        )
        build_prompt = patch.object(
            wifi_analyzer,
            "build_prompt",
            return_value=("system", "user"),
        )
        with (
            patch.object(
                wifi_analyzer,
                "discover_and_parse",
                return_value=(self.result, "problem details"),
            ),
            generate_report as generate,
            build_prompt as build,
            patch.object(wifi_analyzer, "load_config", return_value=self.config),
            patch.object(wifi_analyzer, "chat", return_value="diagnosis"),
            patch.object(
                sys,
                "argv",
                ["wifi_analyzer.py", "case", "--no-stream"],
            ),
            patch("sys.stdout", new_callable=io.StringIO),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            wifi_analyzer.main()

        generate.assert_called_once_with(self.result, problem_desc=None)
        build.assert_called_once_with("problem details", "extracted data")

    def test_extract_only_report_keeps_problem_description(self):
        generate_report = patch.object(
            wifi_analyzer,
            "generate_report",
            return_value="self-contained extracted data",
        )
        with (
            patch.object(
                wifi_analyzer,
                "discover_and_parse",
                return_value=(self.result, "problem details"),
            ),
            generate_report as generate,
            patch.object(wifi_analyzer, "load_config") as load_config,
            patch.object(
                sys,
                "argv",
                ["wifi_analyzer.py", "case", "--extract-only"],
            ),
            patch("sys.stdout", new_callable=io.StringIO),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            wifi_analyzer.main()

        generate.assert_called_once_with(
            self.result,
            problem_desc="problem details",
        )
        load_config.assert_not_called()

    def test_help_subprocess_smoke(self):
        repo_root = Path(__file__).resolve().parent
        proc = subprocess.run(
            [sys.executable, "wifi_analyzer.py", "--help"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("WiFi", proc.stdout)


if __name__ == "__main__":
    unittest.main()
