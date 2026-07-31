# 新建问题单

创建一个新的 WiFi 问题分析目录。

## 参数

$ARGUMENTS — 问题单编号或名称（如 4123、dhcp慢）

## 步骤

1. 用 `$ARGUMENTS` 作为目录名，创建目录。
2. 从 `templates/问题描述模板.md` 复制模板到新目录下，生成 `问题描述.md`。
3. 提示用户：
   - 将抓包文件放入该目录（支持 `.pcapng`、`.pkt`；classic `.pcap` 请先用 Wireshark 转换为 `.pcapng`）
   - 按模板填写 `问题描述.md`，重点填写：关键 MAC 地址、问题发生时间段、抓包方式
   - 填好后用 `/analyze-wifi <目录名>` 运行分析
