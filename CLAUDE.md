# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

A WiFi packet analysis toolkit with two modes:

1. **Standalone CLI** (`wifi_analyzer.py`): Set an API key, run one command, get an AI-generated diagnosis report. Supports any OpenAI-compatible API (OpenAI, DeepSeek, Ollama, etc.) and native Anthropic API.
2. **Claude Code skill** (`/analyze-wifi`): For Claude Code users — the skill guides Claude through the same analysis methodology.

Both modes share the same data extraction layer (`analyze.py` + parsers) and analysis methodology (embedded in `prompt_builder.py` and `.claude/commands/analyze-wifi.md`).

**The AI does the analysis, not the script.**

Pure Python 3.10+, zero external dependencies (stdlib only).

## Architecture

```
Mode 1 — Standalone CLI:
  python3 wifi_analyzer.py <directory>
         │
         ├─ pcapng_parser.py / omnipeek_parser.py  →  result dict
         ├─ analyze.py  →  extracted Markdown report
         ├─ prompt_builder.py  →  system prompt + user prompt
         └─ llm_client.py  →  LLM API call  →  Diagnosis report

Mode 2 — Claude Code skill:
  /analyze-wifi <directory>
         │
         ├─ analyze.py  →  _extracted.md
         └─ Claude reads _extracted.md + 问题描述.md  →  Diagnosis report
```

### `pcapng_parser.py` — pcapng binary parser (shared 802.11 parsing layer)

- `PcapngReader`: Iterator over pcapng blocks. Handles timestamp resolution auto-detection (IDB option 9 `if_tsresol`; falls back to nanoseconds if computed time >1 day in future).
- `parse_radiotap()`: Walks present-bitmask chain (bit 31 = extension), parses fields with correct alignment. Stops at bit 14+ (vendor-specific, unknown sizes).
- `parse_frame()`: 802.11 MAC header. Action frame BA details in `_parse_action()`.
- `_parse_dhcp_from_frame()`: Deep inspection: LLC/SNAP → IPv4 → UDP → DHCP options. Only on unencrypted data frames (skips Protected frames).
- `parse_capture()`: High-level entry. Returns the unified dict (see below).
- `omnipeek_parser.py` imports `parse_frame`, `_parse_dhcp_from_frame`, `mac_str` from here.

**Byte-order gotchas**: pcapng block headers are little-endian; BA Parameter Set fields are big-endian (`>H`). DELBA body: category at payload[0], action at payload[1], Parameter Set at payload[2:4], reason at payload[4:6].

### `hw_metrics.py` — hardware-level metrics extraction (standalone)

- `analyze_hw_metrics(filepath, target_macs)`: Extracts radiotap-layer hardware diagnostics from pcapng. Returns signal histogram, 5-second window stability, noise floor, frame size distribution, antenna/rate data, per-second stats, retry-vs-normal signal comparison.
- `print_report(results, target_macs)`: Terminal report with 11 analysis dimensions: radiotap field availability, signal distribution, signal stability, noise floor, SNR estimation, retry signal comparison, frame size distribution (A-MPDU/AMSDU efficiency), legacy rate distribution, antenna diversity, per-second throughput/retransmit trend, diagnostic summary.
- Dependencies: imports `PcapngReader`, `parse_radiotap`, `parse_frame`, `DATA` from `pcapng_parser.py`.
- Usage: `python3 hw_metrics.py <pcapng> [mac1] [mac2] ...`

### `omnipeek_parser.py` — OmniPeek/AiroPeek .pkt parser

- `parse_omnipeek()`: Returns same unified dict structure.
- Uses `ad 00 00 00` marker alternation: even-indexed = metadata TLVs, odd-indexed = frame data.
- `_scan_raw_dhcp()`: Fallback that searches raw file bytes for DHCP magic cookie (`63 82 53 63`), walks backward 236 bytes to BOOTP header.
- Timestamps currently use file offsets (approximate). TLV timestamp parsing has edge cases.

**OmniPeek metadata TLV tags**: `0x0001` = timestamp low, `0x0002` = timestamp high, `0x0006` = signal (signed int32), `0x0007` = noise (signed int32), `0x0015` = end marker.

### Unified parser return dict

Both parsers return the same structure:

```python
{
    'meta':              {filepath, file_size_mb, total_packets, filtered_packets, reader_total, duration, first_ts, interfaces, format},
    'frame_stats':       dict,   # frame type/subtype counts
    'ba_events':         list,   # ADDBA Request/Response/DELBA with TID, buffer size, reason
    'disconnect_events': list,   # Deauth/Disassociation with reason codes
    'assoc_events':      list,   # Auth/Assoc/Reassoc request/response
    'dhcp_events':       list,   # DHCP Discover/Offer/Request/ACK/NAK with XID
    'signal_data':       dict,   # per-MAC signal strength time series
    'retransmit_stats':  dict,   # per-MAC retransmit counts and rates
    'data_timestamps':   dict,   # per-MAC data frame timestamps for throughput estimation
}
```

### `analyze.py` — data extraction + issue detection

Runs the appropriate parser, generates Markdown report with frame statistics, auto-detected issues, timelines, signal and retransmit tables.

Key exports used by `wifi_analyzer.py`: `generate_report()`, `find_files_in_dir()`.

**Format auto-detection** (lines ~788-797): content-based, checks `.pkt` extension then magic bytes.

**Issue detection thresholds** (in `detect_*_issues()` functions):
- BA: thrashing >0.5 DELBA/sec, cycles <2s apart, storms >5 DELBA in 1s
- Signal: weak < -70 dBm, sudden drop >15 dBm
- Retransmit: MEDIUM >5%, HIGH >15%
- Disconnect: frequent >3 events
- DHCP: NAK, missing Offer, Request-without-ACK, multiple rounds

### `wifi_analyzer.py` — standalone CLI entry point (AI-powered)

Single command: `python3 wifi_analyzer.py <directory>`. Wires together file discovery, parsing, report generation, prompt construction, and LLM API call with streaming output.

Config priority: CLI args > env vars (`WIFI_ANALYZER_*`) > `~/.wifi_analyzer.json`.

### `llm_client.py` — universal LLM client

Pure stdlib (`urllib.request`). Two code paths:
- OpenAI-compatible (`/v1/chat/completions`) — covers OpenAI, DeepSeek, Ollama, vLLM, etc.
- Anthropic native (`/v1/messages`) — for direct Claude API

Provider auto-detection from URL/model name. SSE streaming, retry with backoff on 429/5xx.

### `prompt_builder.py` — analysis prompt + truncation

Embeds the full analysis methodology as `ANALYSIS_METHODOLOGY` string constant. Section-aware truncation for large captures (preserves issue detection section, truncates BA/DHCP tables).

### Skills (`.claude/commands/`)

- `/analyze-wifi` — Claude Code skill. Same methodology as `prompt_builder.py.ANALYSIS_METHODOLOGY` (keep in sync).
- `/new-case` — Scaffolding: creates case directory, copies `templates/问题描述模板.md`.

## Commands

```bash
# AI-powered analysis (main entry point)
python3 wifi_analyzer.py <directory>
python3 wifi_analyzer.py <directory> --api-key sk-xxx --model gpt-4o
python3 wifi_analyzer.py <directory> --base-url https://api.deepseek.com --model deepseek-chat
python3 wifi_analyzer.py <directory> --save-report report.md
python3 wifi_analyzer.py <directory> --extract-only --save-report extracted.md

# Standalone data extraction (no AI)
python3 analyze.py <directory> --report <directory>/_extracted.md
python3 analyze.py <file> --mac <addr> --from <sec> --to <sec> --report out.md
python3 analyze.py <directory> --brief

# Hardware metrics deep analysis
python3 hw_metrics.py <pcapng>
python3 hw_metrics.py <pcapng> <mac1> <mac2>
```

## Extending

**New detection in the parser**: add `detect_*_issues()` in `analyze.py`, return `{severity, category, desc, detail}` dicts. Call in both `generate_report()` and `print_terminal_report()`.

**New capture format**: add parser (like `omnipeek_parser.py`), return same dict structure. Update `analyze.py` `main()` to detect format.

**New analysis dimension**: update both `prompt_builder.py.ANALYSIS_METHODOLOGY` and `.claude/commands/analyze-wifi.md` (keep in sync).
