# AGENTS.md

## Project

WiFi packet capture analysis toolkit. Pure Python 3.10+, zero external dependencies (stdlib only). No `requirements.txt`, no build step, no test framework. Just run `.py` files directly.

## Key Commands

```bash
python3 wifi_analyzer.py <directory>                        # AI-powered analysis (needs API key)
python3 analyze.py <directory> --report out.md              # Data extraction only, no AI
python3 analyze.py <file> --mac AA:BB:CC:DD:EE:FF --from 10 --to 60 --report out.md
python3 hw_metrics.py <pcapng>                              # Hardware-level metrics
python3 hw_metrics.py <pcapng> <mac1> <mac2>                # Filtered to specific MACs
```

No lint, typecheck, or test commands exist. Verify changes by running the relevant script against a capture file.

## Architecture

```
wifi_analyzer.py          CLI entry point, wires everything together
├── pcapng_parser.py      Binary pcapng/802.11 parser (shared parsing layer)
├── omnipeek_parser.py    OmniPeek .pkt parser (imports from pcapng_parser)
├── analyze.py            Data extraction + issue detection + report generation
├── hw_metrics.py         Radiotap hardware diagnostics (standalone)
├── prompt_builder.py     LLM prompt construction (embeds ANALYSIS_METHODOLOGY)
└── llm_client.py         Universal LLM client (OpenAI-compatible + Anthropic)
```

## Critical Conventions

- **Both parsers must return the same unified dict** (see `CLAUDE.md` for schema). When adding a new parser, match this structure exactly.
- **`prompt_builder.py.ANALYSIS_METHODOLOGY` and `.claude/commands/analyze-wifi.md` must stay in sync.** Editing one requires editing the other.
- **New issue detectors**: add `detect_*_issues()` in `analyze.py`, return `{severity, category, desc, detail}` dicts. Wire into both `generate_report()` and `print_terminal_report()`.
- **Config priority**: CLI args > env vars (`WIFI_ANALYZER_*`) > `~/.wifi_analyzer.json`.
- **Provider auto-detection**: Anthropic URL or `claude`-prefixed model → Anthropic API; everything else → OpenAI-compatible.

## Binary Parsing Gotchas

- pcapng block headers: **little-endian**. BA Parameter Set fields: **big-endian** (`>H`).
- `parse_radiotap()` walks present-bitmask chain (bit 31 = extension). Stops at bit 14+ (vendor-specific, unknown sizes).
- Timestamp resolution: IDB option 9 `if_tsresol`; falls back to nanoseconds if computed time is >1 day in the future.
- `_parse_dhcp_from_frame()` only processes **unencrypted** data frames (skips Protected bit set).

## Issue Detection Thresholds

- BA thrashing: >0.5 DELBA/sec, cycles <2s, storms >5 DELBA in 1s
- Signal: weak < -70 dBm, sudden drop >15 dBm
- Retransmit: MEDIUM >5%, HIGH >15%
- Disconnect: frequent >3 events
- DHCP: NAK, missing Offer, Request-without-ACK, multiple rounds

## File Artifacts

`_extracted.md` and `_filtered.md` are generated outputs (gitignored). Do not edit or commit them.

## Existing Instruction Files

- `CLAUDE.md` — comprehensive architecture and extension guide (authoritative reference for parser internals, data flow, and extension patterns)
- `.claude/commands/analyze-wifi.md` — Claude Code skill, mirrors `prompt_builder.py.ANALYSIS_METHODOLOGY`
- `.claude/commands/new-case.md` — case scaffolding command
