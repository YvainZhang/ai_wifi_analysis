#!/usr/bin/env python3
"""
WiFi Analyzer — AI-powered WiFi packet capture analysis tool.

Usage:
    python3 wifi_analyzer.py <directory>
    python3 wifi_analyzer.py <directory> --save-report report.md
    python3 wifi_analyzer.py <directory> --extract-only

Configuration (priority: CLI args > env vars > ~/.wifi_analyzer.json):
    WIFI_ANALYZER_API_KEY    API key
    WIFI_ANALYZER_BASE_URL   API endpoint (e.g. https://api.openai.com)
    WIFI_ANALYZER_MODEL      Model name (e.g. gpt-4o, claude-sonnet-4-20250514)
    WIFI_ANALYZER_PROVIDER   "openai" or "anthropic" (auto-detected if unset)
"""

import argparse
import json
import os
import sys
import math
from urllib.parse import urlparse

from analyze import (
    apply_event_filter,
    detect_capture_format,
    generate_report,
    parse_capture_file,
    resolve_input_files,
)
from llm_client import LLMConfig, chat_stream, chat
from prompt_builder import build_prompt


CONFIG_FILE = os.path.expanduser("~/.wifi_analyzer.json")

DEFAULT_CONFIG = {
    "base_url": "https://api.openai.com",
    "model": "gpt-4o",
    "provider": "",
    "max_tokens": 8192,
    "temperature": 0.3,
}


def load_config_file() -> dict:
    """Load config from ~/.wifi_analyzer.json if it exists."""
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                value = json.load(f)
                if not isinstance(value, dict):
                    raise ValueError("配置根节点必须是 JSON 对象")
                return value
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: 无法读取配置文件 {CONFIG_FILE}: {e}", file=sys.stderr)
    return {}


def load_config(args) -> LLMConfig:
    """Merge config from file, env vars, and CLI args. CLI wins."""
    file_cfg = load_config_file()

    # API key: CLI > env > file
    api_key = (
        args.api_key
        or os.environ.get("WIFI_ANALYZER_API_KEY")
        or file_cfg.get("api_key")
        or ""
    )

    # Base URL: CLI > env > file > default
    base_url = (
        args.base_url
        or os.environ.get("WIFI_ANALYZER_BASE_URL")
        or file_cfg.get("base_url")
        or DEFAULT_CONFIG["base_url"]
    )

    # Model: CLI > env > file > default
    model = (
        args.model
        or os.environ.get("WIFI_ANALYZER_MODEL")
        or file_cfg.get("model")
        or DEFAULT_CONFIG["model"]
    )

    # Provider: CLI > env > file (empty = auto-detect)
    provider = (
        args.provider
        or os.environ.get("WIFI_ANALYZER_PROVIDER")
        or file_cfg.get("provider")
        or DEFAULT_CONFIG["provider"]
    )

    # Numeric settings
    max_tokens = file_cfg.get("max_tokens", DEFAULT_CONFIG["max_tokens"])
    temperature = file_cfg.get("temperature", DEFAULT_CONFIG["temperature"])
    if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
        raise ValueError("max_tokens 必须是正整数")
    if not isinstance(temperature, (int, float)) or isinstance(temperature, bool) or not math.isfinite(temperature) or temperature < 0:
        raise ValueError("temperature 必须是非负有限数字")
    if provider and provider not in ("openai", "anthropic"):
        raise ValueError("provider 必须是 openai 或 anthropic")

    return LLMConfig(
        api_key=api_key,
        base_url=base_url,
        model=model,
        provider=provider,
        max_tokens=max_tokens,
        temperature=temperature,
    )


def is_local_endpoint(base_url):
    """Local OpenAI-compatible servers (Ollama/vLLM) do not need a key."""
    try:
        return urlparse(base_url).hostname in {"localhost", "127.0.0.1", "::1"}
    except ValueError:
        return False


def positive_int(value):
    try:
        number = int(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError("必须为正整数") from e
    if number <= 0:
        raise argparse.ArgumentTypeError("必须为正整数")
    return number


def discover_and_parse(input_path, args):
    """Discover files, parse capture, return (result, problem_desc)."""
    try:
        capture_file, desc_file = resolve_input_files(input_path, args.desc)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Read problem description
    problem_desc = ""
    if desc_file and os.path.isfile(desc_file):
        with open(desc_file, "r", encoding="utf-8") as f:
            problem_desc = f.read()
        print(f"  问题描述: {desc_file}", file=sys.stderr)
    else:
        print("  Warning: 未找到问题描述文件，分析质量可能受影响", file=sys.stderr)

    try:
        capture_format = detect_capture_format(capture_file)
    except (OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    if capture_format == "omnipeek":
        print(f"  正在解析 {capture_file} (OmniPeek 格式) ...", file=sys.stderr)
    else:
        print(f"  正在解析 {capture_file} ...", file=sys.stderr)
    mac_filter = [m.strip() for m in args.mac.split(",")] if args.mac else None
    result, _capture_format = parse_capture_file(
        capture_file,
        mac_filter=mac_filter,
        time_from=args.time_from,
        time_to=args.time_to,
        capture_format=capture_format,
    )
    apply_event_filter(result, tid=args.tid, event_type=args.event_type)

    return result, problem_desc


def main():
    parser = argparse.ArgumentParser(
        description="WiFi 抓包 AI 分析工具 — 自动提取 + AI 根因定位",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基本用法（需要设置 API key）
  python3 wifi_analyzer.py ./case_4123

  # 指定 API key
  python3 wifi_analyzer.py ./case_4123 --api-key sk-xxx

  # 使用 DeepSeek
  python3 wifi_analyzer.py ./case_4123 --base-url https://api.deepseek.com --model deepseek-chat

  # 使用本地 Ollama
  python3 wifi_analyzer.py ./case_4123 --base-url http://localhost:11434 --model llama3

  # 只提取数据，不调用 AI
  python3 wifi_analyzer.py ./case_4123 --extract-only --save-report extracted.md

配置文件 ~/.wifi_analyzer.json:
  {
    "api_key": "sk-xxx",
    "base_url": "https://api.openai.com",
    "model": "gpt-4o"
  }
        """,
    )

    parser.add_argument("input", help="包含抓包文件和问题描述的目录，或抓包文件路径")

    # LLM config
    llm_group = parser.add_argument_group("AI 配置")
    llm_group.add_argument("--api-key", help="API key (或设置 WIFI_ANALYZER_API_KEY 环境变量)")
    llm_group.add_argument("--base-url", help="API 地址 (默认: https://api.openai.com)")
    llm_group.add_argument("--model", help="模型名称 (默认: gpt-4o)")
    llm_group.add_argument("--provider", choices=["openai", "anthropic"], help="API 类型 (自动检测)")
    llm_group.add_argument("--max-tokens", type=positive_int, help="最大输出 token 数 (默认: 8192)")

    # Output
    out_group = parser.add_argument_group("输出控制")
    out_group.add_argument("--save-report", help="保存诊断报告到文件")
    out_group.add_argument("--no-stream", action="store_true", help="禁用流式输出")
    out_group.add_argument("--extract-only", action="store_true", help="只提取数据，不调用 AI")

    # Filters (same as analyze.py)
    filt_group = parser.add_argument_group("数据过滤")
    filt_group.add_argument("--desc", help="问题描述文件路径")
    filt_group.add_argument("--mac", help="过滤 MAC 地址，逗号分隔")
    filt_group.add_argument("--tid", type=int, help="过滤 TID")
    filt_group.add_argument("--from", dest="time_from", type=float, help="起始时间 (秒)")
    filt_group.add_argument("--to", dest="time_to", type=float, help="结束时间 (秒)")
    filt_group.add_argument("--type", dest="event_type", choices=["ba", "disconnect", "assoc", "mgmt", "signal"],
                            help="过滤事件类型")

    args = parser.parse_args()

    # Step 1: Parse capture
    print("=== WiFi Analyzer ===", file=sys.stderr)
    result, problem_desc = discover_and_parse(args.input, args)
    print(f"  解析完成: {result['meta']['total_packets']} 包, {result['meta']['duration']:.2f}s", file=sys.stderr)

    # Step 2: Generate extracted report. The AI prompt adds the description
    # separately, while extract-only reports remain self-contained.
    extracted_report = generate_report(
        result,
        problem_desc=problem_desc if args.extract_only else None,
    )

    # Extract-only mode
    if args.extract_only:
        if args.save_report:
            with open(args.save_report, "w", encoding="utf-8") as f:
                f.write(extracted_report)
            print(f"  提取报告已保存到: {args.save_report}", file=sys.stderr)
        else:
            print(extracted_report)
        return

    # Step 3: Load LLM config
    try:
        config = load_config(args)
    except ValueError as e:
        print(f"Error: 配置无效: {e}", file=sys.stderr)
        sys.exit(2)
    if args.max_tokens is not None:
        config.max_tokens = args.max_tokens

    if not config.api_key and not is_local_endpoint(config.base_url):
        print("Error: 未配置 API key。请通过以下方式之一设置:", file=sys.stderr)
        print("  1. --api-key <key>", file=sys.stderr)
        print("  2. export WIFI_ANALYZER_API_KEY=<key>", file=sys.stderr)
        print(f"  3. 在 {CONFIG_FILE} 中添加 \"api_key\": \"<key>\"", file=sys.stderr)
        sys.exit(1)

    print(f"  AI 模型: {config.provider} / {config.model}", file=sys.stderr)
    print(f"  API 地址: {config.base_url}", file=sys.stderr)

    # Step 4: Build prompt
    system, user = build_prompt(problem_desc, extracted_report)
    print(f"  Prompt 长度: {len(system) + len(user)} 字符", file=sys.stderr)

    # Step 5: Call LLM
    print("  正在分析...\n", file=sys.stderr)

    report_lines = []
    try:
        if args.no_stream:
            report = chat(config, system, user)
            report_lines.append(report)
            print(report)
        else:
            for chunk in chat_stream(config, system, user):
                report_lines.append(chunk)
                print(chunk, end="", flush=True)
            print()  # final newline
    except KeyboardInterrupt:
        print("\n\n  分析已中断", file=sys.stderr)
    except Exception as e:
        print(f"\nError: AI 调用失败: {e}", file=sys.stderr)
        sys.exit(1)

    # Step 6: Save report if requested
    if args.save_report and report_lines:
        full_report = "".join(report_lines)
        with open(args.save_report, "w", encoding="utf-8") as f:
            f.write(full_report)
        print(f"\n  诊断报告已保存到: {args.save_report}", file=sys.stderr)


if __name__ == "__main__":
    main()
