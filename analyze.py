#!/usr/bin/env python3
"""
WiFi pcapng Analyzer — 自动分析 802.11 空口抓包并生成报告。
纯 Python 实现，无外部依赖。

Usage:
    python3 analyze.py <pcapng_file> [options]
    python3 analyze.py <directory>            # 自动查找目录下的 .pcapng 和 问题描述.md

Options:
    --desc <file>       问题描述文件 (.md)
    --mac <addr>        过滤指定 MAC 地址 (可多次使用，逗号分隔)
    --tid <n>           过滤指定 TID
    --from <sec>        起始时间 (秒，相对抓包起始)
    --to <sec>          结束时间 (秒，相对抓包起始)
    --type <type>       过滤事件类型: ba | disconnect | assoc | mgmt | signal
    --report <file>     输出 markdown 分析报告到文件
    --brief             精简模式，只输出摘要和问题诊断
"""

import argparse
import os
import sys
from datetime import datetime, timezone
from collections import defaultdict

from pcapng_parser import parse_capture


# ============================================================
# Analysis helpers
# ============================================================

DEAUTH_REASONS = {
    0: "Reserved",
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Station leaving / deauthenticating",
    4: "Disassociated due to inactivity",
    5: "AP unable to handle all associated stations",
    6: "Class 2/3 frame from non-authenticated station",
    7: "Station leaving / deassociating",
    8: "Associating / reassociating with other AP",
    9: "Reassociation denied (prior association not confirmed)",
    10: "Association denied (outside BSS)",
    11: "Association denied (outside BSS, not authenticated)",
    13: "Invalid information element",
    14: "MIC failure",
    15: "4-way handshake timeout",
    16: "Group key handshake timeout",
    17: "Information element in 4-way handshake differs",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSNE version",
    22: "Invalid RSNE capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected",
    32: "Robust management frame policy violation",
    36: "STA leaving BSS",
    37: "AP unable to handle all STAs",
    38: "Received frame from unauthenticated STA",
    39: "Received frame from unassociated STA",
    46: "STA does not support mandatory features",
}


def fmt_time(seconds):
    """Format relative timestamp."""
    return "%.3fs" % seconds


def fmt_ts_absolute(epoch_sec):
    """Format absolute timestamp."""
    try:
        return datetime.fromtimestamp(epoch_sec, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except (OSError, ValueError):
        return "?"


def reason_text(code):
    return DEAUTH_REASONS.get(code, "Reason %d (vendor-specific or unknown)" % code)


def identify_roles(frame_stats, ba_events, assoc_events):
    """Guess AP vs STA roles based on frame patterns."""
    # AP sends beacons, STA sends probe requests / association requests
    ap_candidates = set()
    sta_candidates = set()

    for evt in assoc_events:
        if 'Request' in evt['type']:
            sta_candidates.add(evt['src'])
            ap_candidates.add(evt['dst'])
        elif 'Response' in evt['type']:
            ap_candidates.add(evt['src'])
            sta_candidates.add(evt['dst'])

    for evt in ba_events:
        ba = evt['ba']
        if ba['action'] == 'ADDBA Request':
            ap_candidates.add(evt['src'])
            sta_candidates.add(evt['dst'])
        elif ba['action'] == 'DELBA':
            pass  # either side

    # Filter: only keep MACs that appear multiple times
    return ap_candidates, sta_candidates


ISSUE_LAYERS = [
    ('rf_quality', '射频质量 (底层 — 影响上层所有问题)'),
    ('frame_quality', '帧质量 (中层 — 重传/丢包)'),
    ('protocol_ba', '协议/Block Ack (上层 — BA 管理/协议效率)'),
    ('connectivity', '连接性/网络接入 (表层 — 用户可见现象)'),
]

DOMAIN_LABELS = {layer[0]: layer[1] for layer in ISSUE_LAYERS}

def _domain_for(category):
    _CATEGORY_DOMAIN = {
        '弱信号': 'rf_quality',
        '信号突变': 'rf_quality',
        '高重传率': 'frame_quality',
        'BA Thrashing': 'protocol_ba',
        'DELBA/ADDBA 循环': 'protocol_ba',
        'DELBA 风暴': 'protocol_ba',
        'TID 不匹配': 'protocol_ba',
        'ADDBA 失败': 'protocol_ba',
        'DELBA Reason 分析': 'protocol_ba',
        'DELBA 方向': 'protocol_ba',
        '频繁断连': 'connectivity',
        '断连 Reason': 'connectivity',
        'DHCP 多轮交互': 'connectivity',
        'DHCP NAK': 'connectivity',
        'DHCP 无响应': 'connectivity',
        'DHCP Request 被 NAK': 'connectivity',
        'DHCP 重传': 'connectivity',
        'DHCP 客户端': 'connectivity',
        'DHCP 地址信息': 'connectivity',
        'RTS/CTS 开销过高': 'frame_quality',
        'WMM TID 分布不均': 'frame_quality',
        'FCS 错误': 'rf_quality',
        '隐式重传': 'rf_quality',
    }
    return _CATEGORY_DOMAIN.get(category, 'protocol_ba')


def detect_ba_issues(ba_events, duration):
    """Detect Block Ack related problems."""
    issues = []

    delbas = [e for e in ba_events if e['ba']['action'] == 'DELBA']
    addba_reqs = [e for e in ba_events if e['ba']['action'] == 'ADDBA Request']
    addba_resps = [e for e in ba_events if e['ba']['action'] == 'ADDBA Response']
    addba_fails = [e for e in addba_resps if not e['ba'].get('status_ok', True)]

    # DELBA rate
    if delbas and duration > 0:
        delba_rate = len(delbas) / duration
        if delba_rate > 0.5:
            issues.append({
                'severity': 'HIGH',
                'category': 'BA Thrashing',
                'domain': _domain_for('BA Thrashing'),
                'desc': 'DELBA 发送频率过高 (%.1f 次/秒, 共 %d 次)' % (delba_rate, len(delbas)),
                'detail': 'DELBAs 全部来自: %s' % ', '.join(set(e['src'] for e in delbas)),
            })

    # DELBA->ADDBA cycles
    if delbas and addba_reqs:
        # Count rapid cycles: DELBA followed by ADDBA within 2s
        cycles = 0
        for d in delbas:
            for a in addba_reqs:
                if a['time'] > d['time'] and a['time'] - d['time'] < 2.0:
                    cycles += 1
                    break
        if cycles >= 3:
            issues.append({
                'severity': 'HIGH',
                'category': 'DELBA/ADDBA 循环',
                'domain': _domain_for('DELBA/ADDBA 循环'),
                'desc': '检测到 %d 次 DELBA->ADDBA 快速重建循环' % cycles,
                'detail': 'BA 会话反复拆除并重建，通常表示底层传输质量差或 BA 窗口管理异常',
            })

    # TID mismatch
    delba_tids = set(e['ba']['tid'] for e in delbas)
    addba_tids = set(e['ba']['tid'] for e in addba_reqs)
    if delba_tids != addba_tids and delbas and addba_reqs:
        issues.append({
            'severity': 'MEDIUM',
            'category': 'TID 不匹配',
            'domain': _domain_for('TID 不匹配'),
            'desc': 'DELBA TID=%s vs ADDBA TID=%s' % (delba_tids, addba_tids),
            'detail': '拆除和重建的 BA 会话 TID 不一致，可能导致 BA 状态机混乱',
        })

    # ADDBA failures
    if addba_fails:
        issues.append({
            'severity': 'MEDIUM',
            'category': 'ADDBA 失败',
            'domain': _domain_for('ADDBA 失败'),
            'desc': '%d 次 ADDBA Response 返回失败状态' % len(addba_fails),
            'detail': '对端拒绝了 BA 会话建立请求',
        })

    # DELBA burst detection
    if len(delbas) >= 5:
        times = sorted(e['time'] for e in delbas)
        max_burst = 0
        burst_start = 0
        for i in range(len(times)):
            count = 1
            for j in range(i + 1, len(times)):
                if times[j] - times[i] < 1.0:
                    count += 1
                else:
                    break
            if count > max_burst:
                max_burst = count
                burst_start = times[i]
        if max_burst >= 5:
            issues.append({
                'severity': 'HIGH',
                'category': 'DELBA 风暴',
                'domain': _domain_for('DELBA 风暴'),
                'desc': '在 %.3fs 附近 %.1f 秒内爆发 %d 个 DELBA' % (burst_start, 1.0, max_burst),
                'detail': '短时间内大量 DELBA 通常意味着严重的传输问题或状态机死循环',
            })

    # DELBA reason analysis
    if delbas:
        reasons = defaultdict(int)
        for e in delbas:
            reasons[e['ba']['reason']] += 1
        for reason_code, count in reasons.items():
            if count > 3:
                issues.append({
                    'severity': 'INFO',
                    'category': 'DELBA Reason 分析',
                    'domain': _domain_for('DELBA Reason 分析'),
                    'desc': 'reason=%d 出现 %d 次: %s' % (reason_code, count, reason_text(reason_code)),
                })

    # DELBA initiator analysis
    if delbas:
        initiators = defaultdict(int)
        for e in delbas:
            initiators[e['ba']['initiator']] += 1
        if 'Recipient' in initiators and initiators['Recipient'] > 3:
            issues.append({
                'severity': 'INFO',
                'category': 'DELBA 方向',
                'domain': _domain_for('DELBA 方向'),
                'desc': '所有 DELBA 均由 Recipient(接收方) 发起，共 %d 次' % initiators['Recipient'],
                'detail': '接收方主动拆 BA 通常表示：接收窗口溢出、seq hole、或 buffer 管理异常',
            })

    return issues


def detect_disconnect_issues(disconnect_events, duration):
    """Detect disconnect related problems."""
    issues = []
    if not disconnect_events:
        return issues

    deauths = [e for e in disconnect_events if e['type'] == 'Deauthentication']
    disassocs = [e for e in disconnect_events if e['type'] == 'Disassociation']

    if len(disconnect_events) > 3:
        issues.append({
            'severity': 'HIGH',
            'category': '频繁断连',
            'domain': _domain_for('频繁断连'),
            'desc': '共 %d 次断连事件 (%d Deauth + %d Disassoc)' % (
                len(disconnect_events), len(deauths), len(disassocs)),
            'detail': 'Deauth 和 Disassoc 事件汇总',
        })

    # Analyze unique reason codes
    reasons = defaultdict(int)
    for e in disconnect_events:
        reasons[e['reason']] += 1
    for code, count in sorted(reasons.items(), key=lambda x: -x[1]):
        if count >= 2:
            issues.append({
                'severity': 'INFO',
                'category': '断连 Reason',
                'domain': _domain_for('断连 Reason'),
                'desc': 'reason=%d 出现 %d 次: %s' % (code, count, reason_text(code)),
            })

    return issues


def detect_signal_issues(signal_data):
    """Detect signal strength problems."""
    issues = []
    for mac, samples in signal_data.items():
        if len(samples) < 10:
            continue
        values = [s[1] for s in samples]
        avg_s = sum(values) / len(values)
        min_s = min(values)
        max_s = max(values)

        # Check for significant signal drops
        if min_s < -70:
            issues.append({
                'severity': 'MEDIUM',
                'category': '弱信号',
                'domain': _domain_for('弱信号'),
                'desc': '%s 信号最低 %d dBm (avg=%d, max=%d)' % (mac, min_s, avg_s, max_s),
                'detail': '信号低于 -70 dBm 可能导致丢包和重传增加',
            })

        # Detect sudden drops > 15 dBm
        for i in range(1, len(samples)):
            drop = samples[i - 1][1] - samples[i][1]
            if drop > 15:
                issues.append({
                    'severity': 'INFO',
                    'category': '信号突变',
                    'domain': _domain_for('信号突变'),
                    'desc': '%s 在 %.3fs 信号下降 %d dBm (%d -> %d)' % (
                        mac, samples[i][0], drop, samples[i - 1][1], samples[i][1]),
                })
                break  # one per MAC is enough

    return issues


def detect_contention_issues(result):
    """Detect channel contention / WMM imbalance issues."""
    issues = []
    stats = result.get('frame_stats', {})
    ctrl = result.get('ctrl_stats', {})
    tid = result.get('tid_frames', {})
    total_data = stats.get('Data', 0)
    if total_data == 0:
        return issues

    rts = ctrl.get('RTS', 0)
    cts = ctrl.get('CTS', 0)
    rts_cts_ratio = (rts + cts) / total_data * 100
    if rts_cts_ratio > 20:
        issues.append({
            'severity': 'HIGH',
            'category': 'RTS/CTS 开销过高',
            'domain': 'frame_quality',
            'desc': f'RTS/CTS 与数据帧比 {rts_cts_ratio:.1f}% ({rts} RTS + {cts} CTS / {total_data} Data)',
            'detail': 'RTS/CTS > 20% 说明大量数据帧需要先发送 RTS 争用信道，可能存在隐藏节点或信道竞争激烈',
        })
    elif rts_cts_ratio > 10:
        issues.append({
            'severity': 'INFO',
            'category': 'RTS/CTS 开销过高',
            'domain': 'frame_quality',
            'desc': f'RTS/CTS 与数据帧比 {rts_cts_ratio:.1f}% ({rts} RTS + {cts} CTS / {total_data} Data)',
            'detail': 'RTS/CTS > 10%，有一定信道竞争开销',
        })

    if tid:
        TID_AC = {0: 'BE', 1: 'BE', 2: 'BK', 3: 'BK', 4: 'VI', 5: 'VI', 6: 'VO', 7: 'VO'}
        total_qos = sum(tid.values())
        if total_qos > 100:
            vo_vi = sum(tid.get(t, 0) for t in (4, 5, 6, 7))
            pct = vo_vi / total_qos * 100
            if pct > 80:
                issues.append({
                    'severity': 'MEDIUM',
                    'category': 'WMM TID 分布不均',
                    'domain': 'frame_quality',
                    'desc': f'VO/VI 占 QoS 帧 {pct:.1f}%（{vo_vi}/{total_qos}），BE/BK 被挤压',
                    'detail': '视频/语音流量占比过高会导致 BE/BK 流量延迟增大甚至丢包',
                })

    bar = ctrl.get('BAR', 0)
    ba = ctrl.get('BA', 0)
    if total_data > 100 and (bar + ba) > 0:
        ba_ratio = (bar + ba) / total_data * 100
        if ba_ratio > 15:
            issues.append({
                'severity': 'INFO',
                'category': 'BA 会话开销',
                'domain': 'protocol_ba',
                'desc': f'BAR/BA 与数据帧比 {ba_ratio:.1f}% ({bar} BAR + {ba} BA / {total_data} Data)',
                'detail': 'BAR/BA 协商帧占比偏高，检查 BA 窗口是否过小导致频繁请求',
            })

    return issues


def detect_bit_error_issues(result):
    """Detect FCS / CRC errors from radiotap RX flags."""
    issues = []
    fcs = result.get('fcs_errors', 0)
    if fcs > 0:
        stats = result.get('frame_stats', {})
        total_frames = stats.get('Data', 0) + stats.get('Control', 0) + stats.get('Management', 0)
        rate = fcs / (total_frames + fcs) * 100 if (total_frames + fcs) > 0 else 0
        sev = 'HIGH' if rate > 5 else 'MEDIUM' if rate > 1 else 'INFO'
        issues.append({
            'severity': sev,
            'category': 'FCS 错误',
            'domain': 'rf_quality',
            'desc': f'FCS 错误帧 {fcs} 个（错误率 {rate:.2f}%）',
            'detail': 'FCS 错误说明帧在传输过程中损坏，通常由信号弱/噪声/干扰导致',
        })
    return issues


def detect_retransmit_issues(retransmit_stats, total_data_frames):
    """Detect retransmission rate issues."""
    issues = []
    if not retransmit_stats or not total_data_frames:
        return issues

    for mac, count in sorted(retransmit_stats.items(), key=lambda x: -x[1])[:5]:
        rate = 100.0 * count / max(total_data_frames, 1)
        if rate > 5.0:
            issues.append({
                'severity': 'HIGH' if rate > 15 else 'MEDIUM',
                'category': '高重传率',
                'domain': _domain_for('高重传率'),
                'desc': '%s 重传 %d 次 (%.1f%%)' % (mac, count, rate),
                'detail': '高重传率通常表示信道质量差、干扰、或硬件问题',
            })
    return issues


def detect_dhcp_issues(dhcp_events):
    """Detect DHCP interaction problems."""
    issues = []
    if not dhcp_events:
        return issues

    # Group by xid (transaction)
    xid_groups = defaultdict(list)
    for e in dhcp_events:
        xid = e.get('xid', 0)
        xid_groups[xid].append(e)

    total_discover = sum(1 for e in dhcp_events if e['msg_type'] == 1)
    total_offer = sum(1 for e in dhcp_events if e['msg_type'] == 2)
    total_request = sum(1 for e in dhcp_events if e['msg_type'] == 3)
    total_ack = sum(1 for e in dhcp_events if e['msg_type'] == 6)
    total_nak = sum(1 for e in dhcp_events if e['msg_type'] == 5)

    # Multiple DHCP rounds
    if len(xid_groups) > 1:
        issues.append({
            'severity': 'HIGH',
            'category': 'DHCP 多轮交互',
            'domain': _domain_for('DHCP 多轮交互'),
            'desc': '%d 轮 DHCP 尝试, %d Discover / %d Offer / %d Request / %d ACK / %d NAK' % (
                len(xid_groups), total_discover, total_offer, total_request, total_ack, total_nak),
            'detail': '正常入网只需 1 轮 DORA(Discover-Offer-Request-ACK), 多轮说明每轮都失败了',
        })

    # NAK analysis
    if total_nak > 0:
        issues.append({
            'severity': 'HIGH' if total_nak >= 3 else 'MEDIUM',
            'category': 'DHCP NAK',
            'domain': _domain_for('DHCP NAK'),
            'desc': 'AP DHCP Server 发送了 %d 次 NAK (拒绝分配 IP)' % total_nak,
            'detail': 'NAK 表示服务器主动拒绝分配请求的 IP。可能原因：地址池耗尽、IP 冲突、租约表异常、DHCP Server 配置错误',
        })

    # Discover without Offer
    disc_without_offer = 0
    for xid, events in xid_groups.items():
        has_offer = any(e['msg_type'] == 2 for e in events)
        has_discover = any(e['msg_type'] == 1 for e in events)
        if has_discover and not has_offer:
            disc_without_offer += 1
    if disc_without_offer > 0:
        issues.append({
            'severity': 'HIGH',
            'category': 'DHCP 无响应',
            'domain': _domain_for('DHCP 无响应'),
            'desc': '%d 轮 Discover 未收到 Offer' % disc_without_offer,
            'detail': 'AP 的 DHCP Server 未响应 Discover, 可能 DHCP 服务未运行或端口被占用',
        })

    # Request without ACK (but got NAK)
    req_no_ack = 0
    for xid, events in xid_groups.items():
        has_req = any(e['msg_type'] == 3 for e in events)
        has_ack = any(e['msg_type'] == 6 for e in events)
        has_nak = any(e['msg_type'] == 5 for e in events)
        if has_req and not has_ack and has_nak:
            req_no_ack += 1
    if req_no_ack > 0:
        issues.append({
            'severity': 'HIGH',
            'category': 'DHCP Request 被 NAK',
            'domain': _domain_for('DHCP Request 被 NAK'),
            'desc': '%d 轮 Request 收到 NAK 而非 ACK' % req_no_ack,
            'detail': 'AP Offer 了 IP 但随后 NAK 了 Request, 这是 DHCP Server 逻辑异常的典型表现',
        })

    # Retransmissions
    retrans_disc = total_discover - len(xid_groups)
    retrans_req = total_request - len(xid_groups)
    if retrans_disc > 0 or retrans_req > 0:
        issues.append({
            'severity': 'INFO',
            'category': 'DHCP 重传',
            'domain': _domain_for('DHCP 重传'),
            'desc': 'Discover 重传 %d 次, Request 重传 %d 次' % (max(0, retrans_disc), max(0, retrans_req)),
            'detail': '重传表示对端未及时响应, 加剧入网延迟',
        })

    # Client info
    clients = set(e.get('client_mac', '') for e in dhcp_events if e.get('client_mac'))
    hosts = set(e.get('hostname', '') for e in dhcp_events if e.get('hostname'))
    if clients:
        issues.append({
            'severity': 'INFO',
            'category': 'DHCP 客户端',
            'domain': _domain_for('DHCP 客户端'),
            'desc': '客户端 MAC: %s, 主机名: %s' % (', '.join(clients), ', '.join(hosts)),
        })

    # Server info
    servers = set(e.get('server_id', '') for e in dhcp_events if e.get('server_id'))
    req_ips = set(e.get('requested_ip', '') for e in dhcp_events if e.get('requested_ip'))
    if servers or req_ips:
        issues.append({
            'severity': 'INFO',
            'category': 'DHCP 地址信息',
            'domain': _domain_for('DHCP 地址信息'),
            'desc': 'Server: %s, 请求 IP: %s' % (', '.join(servers), ', '.join(req_ips)),
        })

    return issues


def generate_timeline(ba_events, disconnect_events, assoc_events, max_events=100):
    """Generate a merged timeline of key events."""
    events = []
    for e in ba_events:
        ba = e['ba']
        events.append((e['time'], 'BA', e))
    for e in disconnect_events:
        events.append((e['time'], 'DISC', e))
    for e in assoc_events:
        events.append((e['time'], 'ASSOC', e))

    events.sort(key=lambda x: x[0])
    return events[:max_events]


# ============================================================
# Report generation
# ============================================================

def generate_report(result, problem_desc=None, brief=False):
    """Generate analysis report as string."""
    meta = result['meta']
    lines = []

    def w(s=''):
        lines.append(s)

    # Header
    w('# WiFi 抓包分析报告')
    w()
    w('**文件**: %s (%.1f MB)' % (os.path.basename(meta['filepath']), meta['file_size_mb']))
    if meta.get('format'):
        w('**格式**: %s' % meta['format'])
    w('**总包数**: %d' % meta['reader_total'])
    if meta['interfaces']:
        lt = meta['interfaces'][0]['link_type']
        lt_name = {105: '802.11', 127: '802.11 + radiotap'}.get(lt, 'link_type=%d' % lt)
        w('**链路类型**: %s' % lt_name)
    w()

    # Problem description
    if problem_desc:
        w('## 问题描述')
        w()
        w(problem_desc.strip())
        w()

    # Frame statistics
    w('## 帧统计')
    w()
    stats = result['frame_stats']
    total = meta['total_packets']
    type_order = ['Management', 'Control', 'Data']
    for t in type_order:
        count = stats.get(t, 0)
        if count:
            w('- **%s**: %d (%.1f%%)' % (t, count, 100 * count / total))
    w()
    w('| 帧子类型 | 数量 | 占比 |')
    w('|----------|------|------|')
    for k, v in sorted(stats.items(), key=lambda x: -x[1]):
        if '/' in k:
            w('| %s | %d | %.1f%% |' % (k, v, 100 * v / total))
    w()

    # Issue diagnosis
    all_issues = []
    all_issues.extend(detect_ba_issues(result['ba_events'], meta['duration']))
    all_issues.extend(detect_disconnect_issues(result['disconnect_events'], meta['duration']))
    all_issues.extend(detect_signal_issues(result['signal_data']))
    all_issues.extend(detect_retransmit_issues(
        result['retransmit_stats'], stats.get('Data', 0)))
    all_issues.extend(detect_dhcp_issues(result['dhcp_events']))
    all_issues.extend(detect_contention_issues(result))
    all_issues.extend(detect_bit_error_issues(result))

    if all_issues:
        w('## 问题诊断')
        w()
        sev_order = {'HIGH': 0, 'MEDIUM': 1, 'INFO': 2}
        domain_groups = defaultdict(list)
        for iss in all_issues:
            domain_groups[iss.get('domain', 'protocol_ba')].append(iss)
        for domain, domain_label in ISSUE_LAYERS:
            group = domain_groups.get(domain)
            if not group:
                continue
            w('### %s' % domain_label)
            w()
            group.sort(key=lambda x: sev_order.get(x['severity'], 9))
            for iss in group:
                marker = {'HIGH': '!!', 'MEDIUM': '!', 'INFO': 'i'}[iss['severity']]
                w('**[%s]** [%s] %s' % (marker, iss['category'], iss['desc']))
                if 'detail' in iss:
                    w('> %s' % iss['detail'])
                w()
    else:
        w('## 问题诊断')
        w()
        w('未检测到明显异常。')
        w()

    if brief:
        return '\n'.join(lines)

    # BA details
    ba_events = result['ba_events']
    if ba_events:
        w('## Block Ack 详细时间线')
        w()
        delbas = [e for e in ba_events if e['ba']['action'] == 'DELBA']
        addba_reqs = [e for e in ba_events if e['ba']['action'] == 'ADDBA Request']
        addba_resps = [e for e in ba_events if e['ba']['action'] == 'ADDBA Response']

        w('- ADDBA Request: %d' % len(addba_reqs))
        w('- ADDBA Response: %d (失败: %d)' % (
            len(addba_resps),
            sum(1 for e in addba_resps if not e['ba'].get('status_ok', True))))
        w('- DELBA: %d' % len(delbas))
        w()

        w('| 时间 | 动作 | 源 -> 目的 | TID | 详情 |')
        w('|------|------|-----------|-----|------|')
        for e in ba_events[:80]:
            ba = e['ba']
            detail_parts = []
            if 'reason' in ba:
                detail_parts.append('reason=%d' % ba['reason'])
            if 'initiator' in ba:
                detail_parts.append(ba['initiator'])
            if 'bufsize' in ba:
                detail_parts.append('bufsize=%d' % ba['bufsize'])
            if 'status_ok' in ba:
                detail_parts.append('OK' if ba['status_ok'] else 'FAIL(status=%d)' % ba['status'])
            if 'policy' in ba:
                detail_parts.append(ba['policy'])
            w('| %s | %s | %s -> %s | %d | %s |' % (
                fmt_time(e['time']), ba['action'], e['src'], e['dst'],
                ba.get('tid', '?'), ', '.join(detail_parts)))
        if len(ba_events) > 80:
            w('| ... | ... | ... | ... | 还有 %d 条 |' % (len(ba_events) - 80))
        w()

    # Disconnect details
    disc_events = result['disconnect_events']
    if disc_events:
        w('## 断连事件')
        w()
        w('| 时间 | 类型 | 源 -> 目的 | Reason |')
        w('|------|------|-----------|--------|')
        for e in disc_events:
            w('| %s | %s | %s -> %s | %d (%s) |' % (
                fmt_time(e['time']), e['type'], e['src'], e['dst'],
                e['reason'], reason_text(e['reason'])))
        w()

    # Association events
    assoc_events = result['assoc_events']
    if assoc_events:
        w('## 关联/认证事件')
        w()
        for e in assoc_events:
            extra = ''
            if 'status' in e:
                extra = ' status=%d' % e['status']
            if 'aid' in e:
                extra += ' AID=%d' % e['aid']
            w('- [%s] %s  %s -> %s%s' % (fmt_time(e['time']), e['type'], e['src'], e['dst'], extra))
        w()

    # Signal stats
    signal_data = result['signal_data']
    if signal_data:
        w('## 信号强度')
        w()
        w('| MAC | 平均 (dBm) | 最低 | 最高 | 样本数 |')
        w('|-----|-----------|------|------|--------|')
        for mac, samples in sorted(signal_data.items(), key=lambda x: -len(x[1])):
            if len(samples) >= 10:
                vals = [s[1] for s in samples]
                w('| %s | %d | %d | %d | %d |' % (
                    mac, sum(vals) // len(vals), min(vals), max(vals), len(vals)))
        w()

    # Retransmit stats
    retx = result['retransmit_stats']
    if retx:
        w('## 重传统计 (Top 10)')
        w()
        w('| MAC | 重传次数 |')
        w('|-----|---------|')
        for mac, count in sorted(retx.items(), key=lambda x: -x[1])[:10]:
            w('| %s | %d |' % (mac, count))
        w()

    # DHCP timeline
    dhcp_events = result['dhcp_events']
    if dhcp_events:
        w('## DHCP 交互时间线')
        w()

        # Group by xid
        xid_groups = defaultdict(list)
        for e in dhcp_events:
            xid_groups[e.get('xid', 0)].append(e)

        for xid, events in sorted(xid_groups.items(), key=lambda x: min(e['time'] for e in x[1])):
            events_sorted = sorted(events, key=lambda e: e['time'])
            first_t = events_sorted[0]['time']
            last_t = events_sorted[-1]['time']
            client = events_sorted[0].get('client_mac', '?')
            host = events_sorted[0].get('hostname', '')

            # Check if this round succeeded
            has_ack = any(e['msg_type'] == 6 for e in events)
            has_nak = any(e['msg_type'] == 5 for e in events)
            result_str = 'ACK(成功)' if has_ack else ('NAK(失败)' if has_nak else '未完成')

            w('### 第 %d 轮 (xid=0x%08x, 客户端=%s%s)' % (
                list(xid_groups.keys()).index(xid) + 1, xid, client,
                ', 主机=%s' % host if host else ''))
            w()

            w('| 时间 | 方向 | 消息类型 | 详情 |')
            w('|------|------|---------|------|')
            for e in events_sorted:
                direction = 'STA->AP' if e['op'] == 'Request' else 'AP->STA'
                detail_parts = []
                if e.get('server_id'):
                    detail_parts.append('server=%s' % e['server_id'])
                if e.get('requested_ip'):
                    detail_parts.append('req_ip=%s' % e['requested_ip'])
                if e.get('hostname'):
                    detail_parts.append('host=%s' % e['hostname'])
                w('| %s | %s | %s | %s |' % (
                    fmt_time(e['time']), direction, e['msg_name'],
                    ', '.join(detail_parts) if detail_parts else '-'))
            w('结果: %s | 持续: %s' % (result_str, fmt_time(last_t - first_t)))
            w()

    return '\n'.join(lines)


# ============================================================
# Terminal output (non-markdown)
# ============================================================

def print_terminal_report(result, brief=False):
    """Print analysis to terminal with colors."""
    meta = result['meta']
    R = '\033[0m'  # reset
    B = '\033[1m'  # bold
    RED = '\033[31m'
    YEL = '\033[33m'
    GRN = '\033[32m'
    CYN = '\033[36m'

    print()
    print('%s=== WiFi 抓包分析 ===%s' % (B, R))
    print('文件: %s (%.1f MB)' % (os.path.basename(meta['filepath']), meta['file_size_mb']))
    print('时长: %.2fs | 包数: %d' % (meta['duration'], meta['reader_total']))
    print()

    # Quick frame summary
    stats = result['frame_stats']
    total = meta['total_packets']
    print('%s帧分布:%s' % (B, R))
    for k, v in sorted(stats.items(), key=lambda x: -x[1])[:8]:
        print('  %-35s %6d  (%4.1f%%)' % (k, v, 100 * v / total))
    print()

    # Issues
    all_issues = []
    all_issues.extend(detect_ba_issues(result['ba_events'], meta['duration']))
    all_issues.extend(detect_disconnect_issues(result['disconnect_events'], meta['duration']))
    all_issues.extend(detect_signal_issues(result['signal_data']))
    all_issues.extend(detect_retransmit_issues(result['retransmit_stats'], stats.get('Data', 0)))
    all_issues.extend(detect_dhcp_issues(result['dhcp_events']))
    all_issues.extend(detect_contention_issues(result))
    all_issues.extend(detect_bit_error_issues(result))

    if all_issues:
        print('%s问题诊断:%s' % (B, R))
        sev_color = {'HIGH': RED, 'MEDIUM': YEL, 'INFO': CYN}
        domain_groups = defaultdict(list)
        for iss in all_issues:
            domain_groups[iss.get('domain', 'protocol_ba')].append(iss)
        for domain, domain_label in ISSUE_LAYERS:
            group = domain_groups.get(domain)
            if not group:
                continue
            print('  %s--- %s ---%s' % (CYN, domain_label, R))
            sev_order = {'HIGH': 0, 'MEDIUM': 1, 'INFO': 2}
            group.sort(key=lambda x: sev_order.get(x['severity'], 9))
            for iss in group:
                c = sev_color.get(iss['severity'], '')
                print('  %s[%s]%s [%s] %s' % (c, iss['severity'], R, iss['category'], iss['desc']))
                if 'detail' in iss:
                    print('         %s' % iss['detail'])
        print()

    if brief:
        return

    # BA timeline (last 30 events)
    ba_events = result['ba_events']
    if ba_events:
        print('%sBA 事件 (最近 %d 条):%s' % (B, min(len(ba_events), 30), R))
        for e in ba_events[-30:]:
            ba = e['ba']
            parts = ['TID=%d' % ba.get('tid', '?')]
            if 'reason' in ba:
                parts.append('reason=%d' % ba['reason'])
            if 'initiator' in ba:
                parts.append(ba['initiator'])
            if 'bufsize' in ba:
                parts.append('buf=%d' % ba['bufsize'])
            if 'status_ok' in ba:
                parts.append('OK' if ba['status_ok'] else 'FAIL')
            print('  [%7.3fs] %-16s %s -> %s  %s' % (
                e['time'], ba['action'], e['src'], e['dst'], ' '.join(parts)))
        print()

    # Disconnect events
    disc = result['disconnect_events']
    if disc:
        print('%s断连事件:%s' % (B, R))
        for e in disc:
            print('  [%7.3fs] %-16s %s -> %s  reason=%d (%s)' % (
                e['time'], e['type'], e['src'], e['dst'], e['reason'], reason_text(e['reason'])))
        print()


# ============================================================
# CLI
# ============================================================

def find_files_in_dir(directory):
    """Auto-discover capture + description in a directory."""
    capture = None
    desc = None
    for f in os.listdir(directory):
        fp = os.path.join(directory, f)
        if not os.path.isfile(fp):
            continue
        if f.endswith('.pcapng') or f.endswith('.pcap') or f.endswith('.pkt'):
            if capture is None:
                capture = fp
        if '问题描述' in f and f.endswith('.md'):
            desc = fp
    return capture, desc


def main():
    parser = argparse.ArgumentParser(
        description='WiFi 802.11 空口抓包分析工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('input', help='pcapng 文件路径或包含抓包的目录')
    parser.add_argument('--desc', help='问题描述文件 (.md)')
    parser.add_argument('--mac', help='过滤 MAC 地址，逗号分隔')
    parser.add_argument('--tid', type=int, help='过滤 TID')
    parser.add_argument('--from', dest='time_from', type=float, help='起始时间 (秒)')
    parser.add_argument('--to', dest='time_to', type=float, help='结束时间 (秒)')
    parser.add_argument('--type', dest='event_type', choices=['ba', 'disconnect', 'assoc', 'mgmt', 'signal'],
                        help='过滤事件类型')
    parser.add_argument('--report', help='输出 markdown 报告到文件')
    parser.add_argument('--brief', action='store_true', help='精简模式')

    args = parser.parse_args()

    # Determine input files
    input_path = args.input
    pcapng_file = None
    desc_file = args.desc

    if os.path.isdir(input_path):
        capture_file, auto_desc = find_files_in_dir(input_path)
        if not capture_file:
            print('Error: 目录下未找到抓包文件 (.pcapng/.pcap/.pkt): %s' % input_path)
            sys.exit(1)
        if not desc_file and auto_desc:
            desc_file = auto_desc
    elif os.path.isfile(input_path):
        capture_file = input_path
    else:
        print('Error: 文件不存在: %s' % input_path)
        sys.exit(1)

    # Read problem description
    problem_desc = None
    if desc_file and os.path.isfile(desc_file):
        with open(desc_file, 'r', encoding='utf-8') as f:
            problem_desc = f.read()

    # Parse MAC filter
    mac_filter = None
    if args.mac:
        mac_filter = [m.strip() for m in args.mac.split(',')]

    # Auto-detect format: check content, not just extension
    is_omnipeek = capture_file.endswith('.pkt')
    if not is_omnipeek:
        # Check magic bytes: OmniPeek starts with 0x7F + 'ver', pcapng starts with SHB/IDB
        try:
            with open(capture_file, 'rb') as f:
                head = f.read(8)
            if len(head) >= 4 and head[0] == 0x7F and head[1:4] == b'ver':
                is_omnipeek = True
        except Exception:
            pass

    if is_omnipeek:
        from omnipeek_parser import parse_omnipeek
        print('正在解析 %s (OmniPeek 格式) ...' % capture_file, file=sys.stderr)
        result = parse_omnipeek(capture_file)
    else:
        print('正在解析 %s ...' % capture_file, file=sys.stderr)
        result = parse_capture(
            capture_file,
            mac_filter=mac_filter,
        time_from=args.time_from,
        time_to=args.time_to,
        )

    # Apply TID filter
    if args.tid is not None:
        result['ba_events'] = [e for e in result['ba_events'] if e['ba'].get('tid') == args.tid]

    # Apply event type filter
    if args.event_type == 'ba':
        result['disconnect_events'] = []
        result['assoc_events'] = []
    elif args.event_type == 'disconnect':
        result['ba_events'] = []
        result['assoc_events'] = []
    elif args.event_type == 'assoc':
        result['ba_events'] = []
        result['disconnect_events'] = []

    # Output
    if args.report:
        report = generate_report(result, problem_desc=problem_desc, brief=args.brief)
        with open(args.report, 'w', encoding='utf-8') as f:
            f.write(report)
        print('报告已保存到: %s' % args.report)
    else:
        print_terminal_report(result, brief=args.brief)

    print('解析完成: %d 包, %.2fs' % (result['meta']['total_packets'], result['meta']['duration']))


if __name__ == '__main__':
    main()
