# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

A **skill-based WiFi packet analysis workflow**. The Python tools convert binary captures (pcapng/OmniPeek) into AI-readable text. The `/analyze-wifi` skill then guides any AI through systematic analysis: data extraction → structured analysis → root cause diagnosis.

**The AI does the analysis, not the script.**

Pure Python 3.10+, zero external dependencies (stdlib only: `struct`, `os`, `collections`, `argparse`, `datetime`).

## Architecture

```
User provides:
  <directory>/问题描述.md  +  capture file (.pcapng/.pcap/.pkt)
         │
         ▼
  wifi_analyzer.py ──→ parse + extract + call LLM API ──→ Diagnosis report

Standalone (no AI):
  analyze.py ──→ _extracted.md (structured text: frames, BA events, DHCP timeline, etc.)
```

### `wifi_analyzer.py` — Main CLI entry point (AI-powered)

Single command: `python3 wifi_analyzer.py <directory>`. Wires together file discovery, parsing, report generation, prompt construction, and LLM API call. Supports all OpenAI-compatible providers and native Anthropic API. Config via CLI args > env vars > `~/.wifi_analyzer.json`.

### `llm_client.py` — Universal LLM client

Pure stdlib (`urllib.request`). Two code paths: OpenAI-compatible (`/v1/chat/completions`) and Anthropic native (`/v1/messages`). SSE streaming, retry with backoff on 429/5xx.

### `prompt_builder.py` — Analysis prompt + truncation

Embeds the full analysis methodology as `ANALYSIS_METHODOLOGY` string constant. Section-aware truncation for large captures (preserves issue detection section, truncates BA/DHCP tables).

### `pcapng_parser.py` — pcapng binary parser (also the shared 802.11 parsing layer)

- `PcapngReader`: Iterator over pcapng blocks. Handles timestamp resolution auto-detection (IDB option 9 `if_tsresol`; falls back to nanoseconds if computed time >1 day in future).
- `parse_radiotap()`: Walks present-bitmask chain (bit 31 = extension), parses fields with correct alignment. Stops at bit 14+ (vendor-specific, unknown sizes).
- `parse_frame()`: 802.11 MAC header. Action frame BA details in `_parse_action()`.
- `_parse_dhcp_from_frame()`: Deep inspection: LLC/SNAP → IPv4 → UDP → DHCP options. Only on unencrypted data frames (skips Protected frames).
- `parse_capture()`: High-level entry. Returns the unified dict (see below).
- `omnipeek_parser.py` imports `parse_frame`, `_parse_dhcp_from_frame`, `mac_str` from here — the 802.11 parsing layer is shared between both parsers.

**Byte-order gotchas**: pcapng block headers are little-endian; BA Parameter Set fields are big-endian (`>H`). DELBA body: category at payload[0], action at payload[1], Parameter Set at payload[2:4], reason at payload[4:6].

### `omnipeek_parser.py` — OmniPeek/AiroPeek .pkt parser

- `parse_omnipeek()`: Returns same unified dict structure.
- Uses `ad 00 00 00` marker alternation: even-indexed = metadata TLVs, odd-indexed = frame data.
- `_scan_raw_dhcp()`: Fallback that searches raw file bytes for DHCP magic cookie (`63 82 53 63`), walks backward 236 bytes to BOOTP header. Deduplication uses 300-byte offset proximity.
- Timestamps currently use file offsets (approximate). TLV timestamp parsing has edge cases.

**OmniPeek metadata TLV tags** (useful for debugging): `0x0001` = timestamp low, `0x0002` = timestamp high, `0x0006` = signal (signed int32), `0x0007` = noise (signed int32), `0x0015` = end marker.

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

### `analyze.py` — CLI tool that feeds the skill

Runs the appropriate parser, generates `_extracted.md` with:
- Frame statistics
- Auto-detected issues (BA thrashing, DHCP NAK, deauth storms, high retransmit, etc.)
- Detailed timelines for BA, DHCP, disconnect, association events
- Signal and retransmit tables

**Format auto-detection** (lines ~788-797): checks `.pkt` extension first, then reads first 4 bytes for OmniPeek magic (`0x7F + 'ver'`) vs pcapng SHB magic. Content-based, so misnamed extensions are handled.

**Issue detection thresholds** (in `detect_*_issues()` functions):
- BA: thrashing >0.5 DELBA/sec, cycles <2s apart, storms >5 DELBA in 1s
- Signal: weak < -70 dBm, sudden drop >15 dBm
- Retransmit: MEDIUM >5%, HIGH >15%
- Disconnect: frequent >3 events
- DHCP: NAK, missing Offer, Request-without-ACK, multiple rounds

### `/analyze-wifi` skill (`.claude/commands/analyze-wifi.md`)

The main deliverable. A step-by-step methodology that any AI can follow:
1. **Collect**: read problem description, run parser, read extracted data
2. **Analyze**: systematic framework covering:
   - Connection flow (Auth → Assoc → DHCP)
   - **Frame quality** (retransmit rate/trends, signal strength/noise, frame size/aggregation, control frame overhead) — mandatory for every analysis
   - Block Ack management
   - DHCP interaction
   - Air efficiency (data frame ratio, throughput estimation)
3. **Root cause**: layered attribution (RF → MAC → protocol → firmware), cross-layer causal chains
4. **Report**: frame quality assessment, protocol flow analysis, prioritized next steps

### `/new-case` skill (`.claude/commands/new-case.md`)

Scaffolding command: creates a new case directory, copies `templates/问题描述模板.md` into it as `问题描述.md`, and instructs the user to place capture files and fill in the template.

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
```

## Extending

**New detection in the parser**: add `detect_*_issues()` in `analyze.py`, return `{severity, category, desc, detail}` dicts. Call in both `generate_report()` and `print_terminal_report()`.

**New capture format**: add parser (like `omnipeek_parser.py`), return same dict structure. Update `analyze.py` `main()` to detect format.

**New analysis dimension**: update the `/analyze-wifi` skill to add new analysis sections.
