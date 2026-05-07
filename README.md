# WiFi Analyzer — AI 驱动的 WiFi 空口抓包分析工具

一键分析 WiFi 空口抓包，自动定位问题根因。

将 pcapng/OmniPeek 抓包文件交给 AI，它会完成从数据提取到根因定位的完整分析：帧质量评估、协议流程分析、时序还原、因果链重建，并给出排查建议。

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/yourname/wifi-analyzer.git
cd wifi-analyzer
```

### 2. 配置 API Key

任选一种方式：

```bash
# 方式一：环境变量
export WIFI_ANALYZER_API_KEY="sk-your-api-key"

# 方式二：配置文件
cat > ~/.wifi_analyzer.json << 'EOF'
{
  "api_key": "sk-your-api-key",
  "base_url": "https://api.openai.com",
  "model": "gpt-4o"
}
EOF
```

### 3. 准备抓包

创建一个目录，放入抓包文件和问题描述：

```bash
mkdir my_case
cp capture.pcapng my_case/
# 编辑问题描述（模板在 templates/问题描述模板.md）
```

### 4. 运行分析

```bash
python3 wifi_analyzer.py my_case
```

AI 会输出完整的诊断报告，包括：帧质量评估、协议流程分析、时序还原、根因定位、排查建议。

## 支持的 AI 提供商

| 提供商 | base_url | model 示例 |
|--------|----------|-----------|
| OpenAI | `https://api.openai.com` | `gpt-4o`, `gpt-4o-mini` |
| Claude | `https://api.anthropic.com` | `claude-sonnet-4-20250514`, `claude-haiku-4-5-20251001` |
| DeepSeek | `https://api.deepseek.com` | `deepseek-chat` |
| Ollama (本地) | `http://localhost:11434` | `llama3`, `qwen2` |
| vLLM | `http://localhost:8000` | 取决于加载的模型 |
| 任意 OpenAI 兼容 | 对应地址 | 对应模型 |

> 设置了 Anthropic URL 或 `claude` 开头的模型名时，自动使用 Anthropic API；否则使用 OpenAI 兼容格式。

## 配置

### 优先级

CLI 参数 > 环境变量 > 配置文件 (`~/.wifi_analyzer.json`)

### 环境变量

| 变量 | 说明 |
|------|------|
| `WIFI_ANALYZER_API_KEY` | API key |
| `WIFI_ANALYZER_BASE_URL` | API 地址 |
| `WIFI_ANALYZER_MODEL` | 模型名称 |
| `WIFI_ANALYZER_PROVIDER` | `openai` 或 `anthropic` |

### 配置文件

`~/.wifi_analyzer.json`：

```json
{
  "api_key": "sk-xxx",
  "base_url": "https://api.openai.com",
  "model": "gpt-4o",
  "max_tokens": 8192,
  "temperature": 0.3
}
```

## 命令参考

```bash
# 基本分析
python3 wifi_analyzer.py <目录>

# 指定 API key 和模型
python3 wifi_analyzer.py <目录> --api-key sk-xxx --model gpt-4o

# 使用 DeepSeek
python3 wifi_analyzer.py <目录> --base-url https://api.deepseek.com --model deepseek-chat

# 使用本地 Ollama
python3 wifi_analyzer.py <目录> --base-url http://localhost:11434 --model llama3

# 保存报告到文件
python3 wifi_analyzer.py <目录> --save-report report.md

# 只提取数据，不调用 AI
python3 wifi_analyzer.py <目录> --extract-only --save-report extracted.md

# 过滤特定 MAC 和时间段
python3 wifi_analyzer.py <目录> --mac AA:BB:CC:DD:EE:FF --from 10 --to 60

# 过滤特定事件类型
python3 wifi_analyzer.py <目录> --type ba
```

## 问题描述模板

分析前请填写 `问题描述.md`（模板在 `templates/问题描述模板.md`）。必须包含：

- **问题概述** — 一句话描述现象
- **关键 MAC 地址** — AP 和 STA 的 MAC
- **抓包说明** — 工具、位置、时长

可选但推荐：测试环境、测试场景、复现步骤、已知线索。

## 架构

```
wifi_analyzer.py          CLI 入口，串联整个流程
  ├── pcapng_parser.py    pcapng 二进制解析器
  ├── omnipeek_parser.py  OmniPeek .pkt 解析器
  ├── analyze.py          数据提取 + 问题检测 + 报告生成
  ├── hw_metrics.py       硬件指标深度分析（信号/噪声/帧大小/天线/速率）
  ├── prompt_builder.py   分析方法论 + prompt 构建
  └── llm_client.py       通用 LLM API 客户端
```

### 工作流程

1. **数据提取** — Python 解析 pcapng/OmniPeek，提取帧统计、BA 事件、断连事件、DHCP 交互、信号强度、重传统计
2. **问题检测** — 自动检测 BA 风暴、DHCP NAK、频繁断连、高重传、弱信号等问题
3. **AI 分析** — 将提取数据和分析方法论发送给 LLM，AI 完成根因定位
4. **报告输出** — 包含帧质量评估、协议流程、时序还原、因果链、排查建议

### 支持的抓包格式

- pcapng (Wireshark, tcpdump)
- pcap
- OmniPeek / AiroPeek .pkt

## 独立使用数据提取

不需要 AI 也能使用数据提取功能：

```bash
# 终端输出（带颜色）
python3 analyze.py <目录>

# 生成 Markdown 报告
python3 analyze.py <目录> --report report.md

# 过滤特定 MAC
python3 analyze.py <文件> --mac AA:BB:CC:DD:EE:FF --report filtered.md
```

## 硬件指标深度分析

`hw_metrics.py` 从 pcapng 抓包中提取 radiotap 层的硬件诊断数据，用于定位射频层问题：

```bash
# 分析所有 MAC
python3 hw_metrics.py capture.pcapng

# 只分析指定 MAC
python3 hw_metrics.py capture.pcapng AA:BB:CC:DD:EE:FF
```

分析维度包括：信号强度分布、5 秒窗口稳定性、噪声底噪、SNR 估算、重传帧与正常帧信号对比、帧大小分布（聚合效率）、数据速率分布、天线分布、每秒吞吐与重传趋势，以及自动诊断总结。

## 纯 Python，零依赖

所有代码仅使用 Python 标准库，无需安装任何第三方包。Python 3.10+。

## License

MIT
