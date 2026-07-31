#!/usr/bin/env python3
"""Deep hardware metrics extraction from pcapng captures.

Extracts signal distribution, noise, frame sizes, per-second trends,
and hardware-level diagnostics beyond the standard analyze.py output.
"""

import struct
import sys
import statistics
from collections import defaultdict
from pcapng_parser import PcapngReader, parse_radiotap, parse_frame, DATA


def analyze_hw_metrics(filepath, target_macs=None):
    target_macs = {mac.lower() for mac in (target_macs or [])}
    reader = PcapngReader(filepath)

    # Per-MAC signal histogram
    sig_hist = defaultdict(lambda: defaultdict(int))   # mac -> signal_val -> count
    # Per-MAC per-5sec signal
    sig_window = defaultdict(lambda: defaultdict(list))  # mac -> 5sec_bin -> [signals]
    # Noise
    noise_vals = []
    noise_hist = defaultdict(int)

    # Radiotap field availability
    rtap_fields = defaultdict(int)
    rtap_total = 0

    # Frame size distribution per MAC (data frames, wifi payload)
    frame_sizes = defaultdict(lambda: defaultdict(int))  # mac -> bucket -> count

    # Antenna distribution per MAC
    antenna_data = defaultdict(lambda: defaultdict(int))  # mac -> antenna -> count

    # Legacy rate distribution per MAC
    rate_data = defaultdict(lambda: defaultdict(int))  # mac -> rate -> count

    # Per-second aggregated stats
    def _new_sec():
        return {
            'data': 0, 'ctrl': 0, 'mgmt': 0,
            'retransmit': 0, 'data_bytes': 0, 'total_bytes': 0,
            'ctrl_bytes': 0, 'mgmt_bytes': 0, 'retransmit_bytes': 0,
            'rts': 0, 'rts_bytes': 0, 'cts': 0, 'cts_bytes': 0,
            'ack': 0, 'ack_bytes': 0, 'bar': 0, 'bar_bytes': 0,
            'ba': 0, 'ba_bytes': 0,
            'fcs_errors': 0, 'rate_sum': 0.0, 'rate_count': 0,
            'sig_samples': defaultdict(list),
        }
    sec_stats = defaultdict(_new_sec)

    # Per-second signal per target MAC
    sec_signal = defaultdict(lambda: defaultdict(list))  # mac -> sec -> [signal]

    retry_sig = defaultdict(list)    # mac -> [signal of retry frames]
    normal_sig = defaultdict(list)   # mac -> [signal of normal frames]

    sec_tid_frames = defaultdict(lambda: defaultdict(int))   # sec -> tid -> count
    sec_tid_bytes = defaultdict(lambda: defaultdict(int))    # sec -> tid -> bytes
    sec_tid_retransmit = defaultdict(lambda: defaultdict(int))  # sec -> tid -> retransmit

    last_seq = {}  # (mac, tid) -> last_seq_num
    sec_seq_gaps = defaultdict(int)  # sec -> gap count

    first_ts = None

    for pkt in reader:
        ts = pkt['timestamp']
        if first_ts is None:
            first_ts = ts
        rel_ts = ts - first_ts
        sec = int(rel_ts)

        raw = pkt['data']
        rtap, wifi_data = parse_radiotap(raw)
        wifi = parse_frame(wifi_data)
        if wifi is None:
            continue

        rtap_total += 1
        for k in rtap:
            rtap_fields[k] += 1

        addr1 = wifi.get('addr1', '')
        addr2 = wifi.get('addr2', '')
        addr1_l = addr1.lower()
        addr2_l = addr2.lower()

        if target_macs and not {addr1_l, addr2_l} & target_macs:
            continue

        sig = rtap.get('dbm_signal')
        noise = rtap.get('dbm_noise')
        rate = rtap.get('rate')
        ant = rtap.get('antenna')
        is_retry = wifi.get('retry', False)
        wifi_len = len(wifi_data)
        total_len = len(raw)

        ftype = wifi['type']
        fsub = wifi['subtype']

        is_data = (ftype == DATA)
        is_ctrl = (ftype == 1)
        is_mgmt = (ftype == 0)

        # --- Signal per transmitter (addr2) ---
        if sig is not None and addr2 and (
                not target_macs or addr2_l in target_macs):
            sig_hist[addr2_l][sig] += 1
            sec_signal[addr2_l][sec].append(sig)
            sig_window[addr2_l][sec // 5].append(sig)

            # Retry vs normal signal
            if is_data:
                if is_retry:
                    retry_sig[addr2_l].append(sig)
                else:
                    normal_sig[addr2_l].append(sig)

        # Noise
        if noise is not None:
            noise_vals.append(noise)
            noise_hist[noise] += 1

        # Rate
        if rate is not None and addr2:
            rate_data[addr2_l][rate] += 1

        # Antenna
        if ant is not None and addr2:
            antenna_data[addr2_l][ant] += 1

        # Frame size (data frames only)
        if is_data and addr2:
            def size_bucket(n):
                if n < 64: return '<64'
                if n < 128: return '64-127'
                if n < 256: return '128-255'
                if n < 512: return '256-511'
                if n < 1024: return '512-1023'
                if n <= 1500: return '1024-1500'
                return '>1500'
            frame_sizes[addr2_l][size_bucket(wifi_len)] += 1

        # Per-second stats
        s = sec_stats[sec]
        if is_data:
            s['data'] += 1
            s['data_bytes'] += wifi_len
            tid = wifi.get('qos_tid')
            if tid is not None:
                sec_tid_frames[sec][tid] += 1
                sec_tid_bytes[sec][tid] += wifi_len
        elif is_ctrl:
            s['ctrl'] += 1
            s['ctrl_bytes'] += wifi_len
            if fsub == 0xB:
                s['rts'] += 1; s['rts_bytes'] += wifi_len
            elif fsub == 0xC:
                s['cts'] += 1; s['cts_bytes'] += wifi_len
            elif fsub == 0xD:
                s['ack'] += 1; s['ack_bytes'] += wifi_len
            elif fsub == 0x8:
                s['bar'] += 1; s['bar_bytes'] += wifi_len
            elif fsub == 0x9:
                s['ba'] += 1; s['ba_bytes'] += wifi_len
        elif is_mgmt:
            s['mgmt'] += 1
            s['mgmt_bytes'] += wifi_len
        s['total_bytes'] += total_len
        if is_retry and is_data:
            s['retransmit'] += 1
            s['retransmit_bytes'] += wifi_len
            tid = wifi.get('qos_tid')
            if tid is not None:
                sec_tid_retransmit[sec][tid] += 1
        if rtap.get('flags', 0) & 0x40:
            s['fcs_errors'] += 1
        if rate is not None:
            s['rate_sum'] += rate
            s['rate_count'] += 1

        # Sequence gap detection
        if is_data and addr2 and 'seq_num' in wifi:
            seq_key = (addr2_l, wifi.get('qos_tid', 0))
            cur_sn = wifi['seq_num']
            prev_sn = last_seq.get(seq_key, -1)
            if prev_sn >= 0:
                gap = (cur_sn - prev_sn) % 4096
                if gap > 1 and gap < 2048:
                    sec_seq_gaps[sec] += gap - 1
            last_seq[seq_key] = cur_sn

    return {
        'sig_hist': dict(sig_hist),
        'sig_window': dict(sig_window),
        'noise_vals': noise_vals,
        'noise_hist': dict(noise_hist),
        'rtap_fields': dict(rtap_fields),
        'rtap_total': rtap_total,
        'frame_sizes': dict(frame_sizes),
        'antenna_data': dict(antenna_data),
        'rate_data': dict(rate_data),
        'sec_stats': dict(sec_stats),
        'sec_signal': dict(sec_signal),
        'retry_sig': dict(retry_sig),
        'normal_sig': dict(normal_sig),
        'sec_tid_frames': dict(sec_tid_frames),
        'sec_tid_bytes': dict(sec_tid_bytes),
        'sec_tid_retransmit': dict(sec_tid_retransmit),
        'sec_seq_gaps': dict(sec_seq_gaps),
        'duration': max(sec_stats.keys()) + 1 if sec_stats else 0,
    }


def print_report(results, target_macs):
    sig_hist = results['sig_hist']
    sig_window = results['sig_window']
    noise_vals = results['noise_vals']
    noise_hist = results['noise_hist']
    rtap_fields = results['rtap_fields']
    rtap_total = results['rtap_total']
    frame_sizes = results['frame_sizes']
    antenna_data = results['antenna_data']
    rate_data = results['rate_data']
    sec_stats = results['sec_stats']
    sec_signal = results['sec_signal']
    retry_sig = results['retry_sig']
    normal_sig = results['normal_sig']

    target_macs = list(target_macs or [])
    if not target_macs:
        sender_metrics = (
            sig_hist, sig_window, frame_sizes, antenna_data, rate_data,
            sec_signal, retry_sig, normal_sig,
        )
        target_macs = sorted({
            mac
            for metric in sender_metrics
            for mac in metric
            if mac
        })

    def fmt_mac(m):
        if ':' in m:
            return m
        return ':'.join(m[i:i+2] for i in range(0, len(m), 2))

    print("=" * 72)
    print("硬件指标深度分析")
    print("=" * 72)

    # 1. Radiotap fields availability
    print("\n## 1. Radiotap 字段可用性")
    print(f"  总帧数: {rtap_total}")
    if rtap_total:
        for k in sorted(rtap_fields, key=lambda x: -rtap_fields[x]):
            v = rtap_fields[k]
            pct = v / rtap_total * 100
            print(f"  {k:>16s}: {v:>7d} ({pct:5.1f}%)")

    # 2. Signal strength distribution
    print("\n## 2. 信号强度分布（直方图）")
    for mac in target_macs:
        mac_l = mac.lower()
        if mac_l not in sig_hist:
            print(f"\n  {mac}: 无数据")
            continue
        print(f"\n  {mac} ({'STA' if mac_l.endswith(':00') else 'AP'}):")
        hist = sig_hist[mac_l]
        total = sum(hist.values())
        for sig_val in sorted(hist.keys(), reverse=True):
            count = hist[sig_val]
            pct = count / total * 100
            bar = '█' * max(1, int(pct / 1))
            print(f"    {sig_val:+3d} dBm | {bar:<50s} {count:>6d} ({pct:5.1f}%)")

    # 3. Signal stability per 5-second window
    print("\n## 3. 信号稳定性（每5秒窗口）")
    for mac in target_macs:
        mac_l = mac.lower()
        if mac_l not in sig_window:
            continue
        print(f"\n  {mac}:")
        print(f"    {'窗口':>10s} | {'平均':>7s} {'最小':>6s} {'最大':>6s} {'标准差':>7s} {'样本':>6s} | 异常")
        print("    " + "-" * 65)

        all_sigs = []
        for w in sig_window[mac_l].values():
            all_sigs.extend(w)
        if all_sigs:
            o_avg = statistics.mean(all_sigs)
            o_std = statistics.stdev(all_sigs) if len(all_sigs) > 1 else 0

        for w in sorted(sig_window[mac_l].keys()):
            vals = sig_window[mac_l][w]
            if not vals:
                continue
            avg = statistics.mean(vals)
            mn = min(vals)
            mx = max(vals)
            std = statistics.stdev(vals) if len(vals) > 1 else 0
            flag = ""
            if std > 5:
                flag += "⚠高抖动 "
            if all_sigs and abs(avg - o_avg) > 8:
                flag += "⚠偏移 "
            rng = mx - mn
            if rng > 20:
                flag += f"⚠波动{rng}dB"
            print(f"    {w*5:>3d}-{(w+1)*5-1:>3d}s | {avg:>+7.1f} {mn:>+6d} {mx:>+6d} {std:>7.1f} {len(vals):>6d} | {flag}")

    # 4. Noise floor
    print("\n## 4. 噪声底噪")
    if noise_vals:
        n_avg = statistics.mean(noise_vals)
        n_std = statistics.stdev(noise_vals) if len(noise_vals) > 1 else 0
        print(f"  平均噪声: {n_avg:.1f} dBm (标准差: {n_std:.1f} dB)")
        print(f"  噪声范围: {min(noise_vals)} ~ {max(noise_vals)} dBm")
        print(f"  样本数: {len(noise_vals)}")
        print("  分布:")
        for n in sorted(noise_hist.keys(), reverse=True):
            c = noise_hist[n]
            pct = c / len(noise_vals) * 100
            bar = '█' * max(1, int(pct / 2))
            print(f"    {n:+3d} dBm | {bar:<40s} {c:>6d} ({pct:.1f}%)")
    else:
        print("  ⚠ 抓包中未包含噪声数据（radiotap dBm_noise 字段缺失）")

    # 5. SNR estimation
    print("\n## 5. SNR 估算")
    if noise_vals and sig_hist:
        n_avg = statistics.mean(noise_vals)
        for mac in target_macs:
            mac_l = mac.lower()
            if mac_l not in sig_hist:
                continue
            hist = sig_hist[mac_l]
            total = sum(hist.values())
            sig_avg = sum(s * c for s, c in hist.items()) / total
            snr = sig_avg - n_avg
            label = ""
            if snr < 10:
                label = "⚠极差 — 几乎无法解码"
            elif snr < 20:
                label = "⚠较差 — 高误码率"
            elif snr < 30:
                label = "一般 — 可用但不够稳定"
            elif snr < 40:
                label = "良好"
            else:
                label = "优秀"
            print(f"  {mac}: 信号 {sig_avg:+.1f} dBm - 噪声 {n_avg:+.1f} dBm = SNR {snr:.1f} dB  {label}")
    else:
        print("  无噪声数据，无法计算 SNR")

    # 6. Retry vs Normal signal comparison
    print("\n## 6. 重传帧 vs 正常帧信号对比")
    for mac in target_macs:
        mac_l = mac.lower()
        rs = retry_sig.get(mac_l, [])
        ns = normal_sig.get(mac_l, [])
        if not rs and not ns:
            continue
        print(f"\n  {mac}:")
        if ns:
            print(f"    正常帧: avg {statistics.mean(ns):+.1f} dBm, "
                  f"范围 [{min(ns):+d}, {max(ns):+d}], 样本 {len(ns)}")
        else:
            print(f"    正常帧: 无数据")
        if rs:
            print(f"    重传帧: avg {statistics.mean(rs):+.1f} dBm, "
                  f"范围 [{min(rs):+d}, {max(rs):+d}], 样本 {len(rs)}")
        else:
            print(f"    重传帧: 无数据")
        if rs and ns:
            diff = statistics.mean(rs) - statistics.mean(ns)
            print(f"    差异: {diff:+.1f} dB ({'重传帧信号更弱' if diff < 0 else '重传帧信号反而更强'} — "
                  f"{'说明重传与信号弱相关' if abs(diff) > 3 else '说明重传非信号因素导致'})")

    # 7. Frame size distribution
    print("\n## 7. 帧大小分布（802.11 帧体长度，仅数据帧）")
    for mac in target_macs:
        mac_l = mac.lower()
        if mac_l not in frame_sizes:
            continue
        print(f"\n  {mac} ({'发送' if mac_l.endswith(':00') else '发送/接收'}):")
        sizes = frame_sizes[mac_l]
        total = sum(sizes.values())
        buckets = ['<64', '64-127', '128-255', '256-511', '512-1023', '1024-1500', '>1500']
        for b in buckets:
            c = sizes.get(b, 0)
            pct = c / total * 100 if total else 0
            bar = '█' * (max(1, int(pct / 2)) if c else 0)
            print(f"    {b:>10s} B | {bar:<40s} {c:>6d} ({pct:.1f}%)")
        # Aggregation efficiency estimate
        large_pct = (sizes.get('>1500', 0) + sizes.get('1024-1500', 0)) / total * 100 if total else 0
        small_pct = (sizes.get('<64', 0) + sizes.get('64-127', 0)) / total * 100 if total else 0
        print(f"    → 大帧(>1024B)占比 {large_pct:.1f}%, 小帧(<128B)占比 {small_pct:.1f}%")
        if small_pct > 50:
            print(f"    ⚠ 小帧占比过高，A-MPDU/A-MSDU 聚合效率可能很低")
        elif large_pct > 60:
            print(f"    → 聚合效率较好")

    # 8. Data rate distribution
    print("\n## 8. 数据速率分布（Radiotap legacy rate 字段）")
    has_rate = False
    for mac in target_macs:
        mac_l = mac.lower()
        if mac_l not in rate_data:
            continue
        has_rate = True
        print(f"\n  {mac}:")
        rates = rate_data[mac_l]
        total = sum(rates.values())
        for r in sorted(rates.keys()):
            c = rates[r]
            pct = c / total * 100
            bar = '█' * max(1, int(pct / 2))
            print(f"    {r:>8.1f} Mbps | {bar:<40s} {c:>6d} ({pct:.1f}%)")
    if not has_rate:
        print("  11ax 帧通常不携带 legacy rate 字段。")
        print("  需要通过 radiotap HE/MCS 字段获取实际调制方式（当前解析器不支持）。")
        print("  建议用 Wireshark 过滤 wlan.ht.mcs 或 wlan.he.mcs 查看。")

    # 9. Antenna diversity
    print("\n## 9. 天线分布")
    for mac in target_macs:
        mac_l = mac.lower()
        if mac_l not in antenna_data:
            continue
        print(f"\n  {mac}:")
        ants = antenna_data[mac_l]
        total = sum(ants.values())
        for a in sorted(ants.keys()):
            c = ants[a]
            pct = c / total * 100
            print(f"    天线 {a}: {c:>6d} ({pct:.1f}%)")

    # 10. Per-second throughput & retransmit trend
    print("\n## 10. 每秒趋势（数据帧数 / 重传率 / 吞吐估算）")
    header = (f"    {'秒':>4s} | {'数据帧':>6s} {'控制帧':>6s} {'管理帧':>5s} "
              f"{'重传':>5s} {'重传率':>7s} | {'数据KB':>7s} {'总计KB':>7s}")
    print(header)
    print("    " + "-" * 75)

    max_sec = max(sec_stats.keys()) if sec_stats else 0
    for sec in sorted(sec_stats.keys()):
        s = sec_stats[sec]
        rr = s['retransmit'] / s['data'] * 100 if s['data'] else 0
        data_kb = s['data_bytes'] / 1024
        total_kb = s['total_bytes'] / 1024
        flag = " ⚠" if rr > 10 else ""
        print(f"    {sec:>4d} | {s['data']:>6d} {s['ctrl']:>6d} {s['mgmt']:>5d} "
              f"{s['retransmit']:>5d} {rr:>6.1f}% | {data_kb:>7.0f} {total_kb:>7.0f}{flag}")

    # 11. WMM / TID distribution
    TID_AC = {0: 'BE', 1: 'BE', 2: 'BK', 3: 'BK', 4: 'VI', 5: 'VI', 6: 'VO', 7: 'VO'}
    print("\n## 11. WMM 接入类别分布（TID → AC）")
    agg_tid = defaultdict(int)
    agg_tid_bytes = defaultdict(int)
    agg_tid_re = defaultdict(int)
    for sec in sorted(sec_stats.keys()):
        for tid, cnt in results.get('sec_tid_frames', {}).get(sec, {}).items():
            agg_tid[tid] += cnt
        for tid, b in results.get('sec_tid_bytes', {}).get(sec, {}).items():
            agg_tid_bytes[tid] += b
        for tid, r in results.get('sec_tid_retransmit', {}).get(sec, {}).items():
            agg_tid_re[tid] += r
    if agg_tid:
        total_qos = sum(agg_tid.values())
        print(f"    {'TID':>3s} {'AC':>3s} {'帧数':>8s} {'占比':>7s} {'字节':>10s} {'重传':>6s} {'重传率':>7s}")
        print("    " + "-" * 55)
        for tid in sorted(agg_tid.keys()):
            ac = TID_AC.get(tid, '??')
            cnt = agg_tid[tid]
            pct = cnt / total_qos * 100
            bts = agg_tid_bytes.get(tid, 0)
            re = agg_tid_re.get(tid, 0)
            rr = re / cnt * 100 if cnt else 0
            flag = " ⚠" if rr > 15 else ""
            print(f"    {tid:>3d} {ac:>3s} {cnt:>8d} {pct:>6.1f}% {bts:>10d} {re:>6d} {rr:>6.1f}%{flag}")
    else:
        print("    无 QoS Data 帧（或 TID 未解析）")

    # 12. Control frame detail
    print("\n## 12. 控制帧细分")
    agg_ctrl = {'RTS': 0, 'CTS': 0, 'ACK': 0, 'BAR': 0, 'BA': 0}
    for sec in sorted(sec_stats.keys()):
        s = sec_stats[sec]
        for k in agg_ctrl:
            agg_ctrl[k] += s.get(k.lower(), 0)
    total_ctrl = sum(agg_ctrl.values())
    if total_ctrl:
        for k, v in agg_ctrl.items():
            pct = v / total_ctrl * 100
            print(f"    {k:>4s}: {v:>6d} ({pct:>5.1f}%)")
        rts_cts = agg_ctrl['RTS'] + agg_ctrl['CTS']
        total_data = sum(s['data'] for s in sec_stats.values())
        if total_data:
            ratio = rts_cts / total_data * 100
            flag = " ⚠ 隐藏节点或高竞争" if ratio > 20 else ""
            print(f"    → RTS/CTS 与数据帧比: {ratio:.1f}%{flag}")
    else:
        print("    无控制帧")

    # 13. FCS error analysis
    print("\n## 13. FCS / 误码分析")
    total_fcs = sum(s.get('fcs_errors', 0) for s in sec_stats.values())
    total_frames = sum(s['data'] + s['ctrl'] + s['mgmt'] for s in sec_stats.values())
    if total_fcs > 0:
        fcs_rate = total_fcs / total_frames * 100 if total_frames else 0
        severity = "⚠⚠ 极高" if fcs_rate > 5 else "⚠ 较高" if fcs_rate > 1 else "轻微"
        print(f"    FCS 错误帧: {total_fcs} (错误率 {fcs_rate:.2f}% — {severity})")
        fcs_secs = [(sec, sec_stats[sec].get('fcs_errors', 0))
                     for sec in sorted(sec_stats.keys()) if sec_stats[sec].get('fcs_errors', 0) > 0]
        if fcs_secs:
            samples = [f"{s}s({c})" for s, c in fcs_secs[:10]]
            print(f"    分布: {', '.join(samples)}")
    elif results.get('rtap_fields', {}).get('flags', 0) > 0:
        print("    FCS 错误帧: 0（抓包中 Radiotap Flags 可用，无误码）")
    else:
        print("    抓包中无 Radiotap Flags 字段，无法检测 FCS 错误")

    # 14. Summary diagnostics
    print("\n## 14. 硬件指标诊断总结")
    issues = []
    for mac in target_macs:
        mac_l = mac.lower()
        if mac_l not in sig_hist:
            continue
        hist = sig_hist[mac_l]
        total = sum(hist.values())
        if total == 0:
            continue

        all_s = []
        for sv, cnt in hist.items():
            all_s.extend([sv] * cnt)
        std = statistics.stdev(all_s) if len(all_s) > 1 else 0
        mn = min(hist.keys())
        mx = max(hist.keys())
        rng = mx - mn

        # Signal instability
        if std > 8:
            issues.append(f"[!!] {mac}: 信号标准差 {std:.1f} dB，极不稳定")
        elif std > 5:
            issues.append(f"[i]  {mac}: 信号标准差 {std:.1f} dB，波动较大")

        # Large range
        if rng > 25:
            issues.append(f"[!!] {mac}: 信号范围 {rng} dB ({mn:+d} ~ {mx:+d} dBm)")

    if noise_vals:
        n_avg = statistics.mean(noise_vals)
        if n_avg > -80:
            issues.append(f"[!!] 噪声底噪偏高: {n_avg:.1f} dBm")
        elif n_avg > -90:
            issues.append(f"[i]  噪声底噪: {n_avg:.1f} dBm")

    # High retransmit windows
    high_retrans = []
    for sec in sorted(sec_stats.keys()):
        s = sec_stats[sec]
        if s['data'] > 10:
            rr = s['retransmit'] / s['data'] * 100
            if rr > 10:
                high_retrans.append((sec, rr))
    if high_retrans:
        secs = [f"{s}s({r:.0f}%)" for s, r in high_retrans[:10]]
        issues.append(f"[!!] {len(high_retrans)} 个秒级窗口重传率 >10%: {', '.join(secs)}")

    # Retry signal analysis
    for mac in target_macs:
        mac_l = mac.lower()
        rs = retry_sig.get(mac_l, [])
        ns = normal_sig.get(mac_l, [])
        if rs and ns and len(rs) > 10:
            diff = statistics.mean(rs) - statistics.mean(ns)
            if abs(diff) > 5:
                issues.append(f"[i]  {mac}: 重传帧信号比正常帧{'弱' if diff < 0 else '强'} {abs(diff):.1f} dB")

    if issues:
        for issue in issues:
            print(f"  {issue}")
    else:
        print("  未发现硬件层异常")


def generate_payload_chart(sec_stats, output_path, zh=False):
    """Generate SVG stacked-area chart of effective payload ratio over time.

    Breaks down WiFi airtime into 6 layers: effective payload, retransmit,
    RTS/CTS (contention), BAR/BA (BA session), ACK, management.
    """
    data = []
    for sec in sorted(sec_stats.keys()):
        s = sec_stats[sec]
        db = s['data_bytes']
        cb = s.get('ctrl_bytes', 0)
        mb = s.get('mgmt_bytes', 0)
        rb = s.get('retransmit_bytes', 0)
        rts_b = s.get('rts_bytes', 0)
        cts_b = s.get('cts_bytes', 0)
        ack_b = s.get('ack_bytes', 0)
        bar_b = s.get('bar_bytes', 0)
        ba_b = s.get('ba_bytes', 0)
        wifi_total = db + cb + mb
        if wifi_total == 0:
            continue
        unique = db - rb
        data.append({
            'sec': sec,
            'payload': unique / wifi_total * 100,
            'retransmit': rb / wifi_total * 100,
            'rts_cts': (rts_b + cts_b) / wifi_total * 100,
            'bar_ba': (bar_b + ba_b) / wifi_total * 100,
            'ack': ack_b / wifi_total * 100,
            'mgmt': mb / wifi_total * 100,
            'rr': s['retransmit'] / s['data'] * 100 if s['data'] else 0,
            'fcs': s.get('fcs_errors', 0),
            'gaps': 0,
            'rate': s['rate_sum'] / s['rate_count'] if s.get('rate_count') else 0,
        })

    if not data:
        print("  No data for chart generation")
        return

    if len(data) > 120:
        bin_sz = 5 if len(data) <= 600 else 10
        binned = []
        for i in range(0, len(data), bin_sz):
            chunk = data[i:i + bin_sz]
            binned.append({
                'sec': chunk[0]['sec'],
                'payload': sum(d['payload'] for d in chunk) / len(chunk),
                'retransmit': sum(d['retransmit'] for d in chunk) / len(chunk),
                'rts_cts': sum(d['rts_cts'] for d in chunk) / len(chunk),
                'bar_ba': sum(d['bar_ba'] for d in chunk) / len(chunk),
                'ack': sum(d['ack'] for d in chunk) / len(chunk),
                'mgmt': sum(d['mgmt'] for d in chunk) / len(chunk),
                'rr': sum(d['rr'] for d in chunk) / len(chunk),
                'fcs': sum(d['fcs'] for d in chunk),
                'gaps': 0,
                'rate': sum(d['rate'] for d in chunk) / len(chunk),
            })
        data = binned

    W, H = 960, 460
    ML, MR, MT, MB = 65, 890, 48, 345
    CW, CH = MR - ML, MB - MT
    n = len(data)
    dx = CW / max(n - 1, 1)

    def xp(i):
        return ML + i * dx

    def yp(pct):
        return MB - pct / 100 * CH

    layers = [
        ('payload', '#22c55e', '有效载荷' if zh else 'Effective Payload'),
        ('retransmit', '#ef4444', '重传' if zh else 'Retransmit'),
        ('rts_cts', '#f97316', 'RTS/CTS 竞争' if zh else 'RTS/CTS Contention'),
        ('bar_ba', '#6366f1', 'BAR/BA 会话' if zh else 'BAR/BA Session'),
        ('ack', '#3b82f6', 'ACK' if zh else 'ACK'),
        ('mgmt', '#a855f7', '管理帧' if zh else 'Management'),
    ]

    cum = [0.0] * n
    polys = []
    for key, color, label in layers:
        bot = cum[:]
        top = [cum[i] + data[i][key] for i in range(n)]
        pts = []
        for i in range(n):
            pts.append(f"{xp(i):.1f},{yp(top[i]):.1f}")
        for i in range(n - 1, -1, -1):
            pts.append(f"{xp(i):.1f},{yp(bot[i]):.1f}")
        polys.append((pts, color, label))
        cum = top

    L = []
    L.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">')
    L.append('  <style>text{font-family:"Helvetica Neue",Helvetica,Arial,sans-serif}</style>')
    L.append(f'  <rect width="{W}" height="{H}" fill="#fff"/>')
    title = 'WiFi 空口效率 — 有效载荷时间分布' if zh else 'WiFi Airtime Efficiency \u2014 Payload Ratio Over Time'
    L.append(f'  <text x="{W // 2}" y="26" text-anchor="middle" font-size="14" font-weight="600" fill="#111827">{title}</text>')

    for pct in (0, 25, 50, 75, 100):
        y = yp(pct)
        L.append(f'  <line x1="{ML}" y1="{y:.1f}" x2="{MR}" y2="{y:.1f}" stroke="#e5e7eb" stroke-width="0.5"/>')
        L.append(f'  <text x="{ML - 5}" y="{y + 3.5:.1f}" text-anchor="end" font-size="9" fill="#6b7280">{pct}%</text>')

    for pts, color, _ in polys:
        L.append(f'  <polygon points="{" ".join(pts)}" fill="{color}" opacity="0.78"/>')

    for i, d in enumerate(data):
        if d['payload'] < 40:
            x = xp(i)
            L.append(f'  <line x1="{x:.1f}" y1="{MT}" x2="{x:.1f}" y2="{MB}" stroke="#ef4444" stroke-width="0.6" stroke-dasharray="3,2" opacity="0.45"/>')

    for i, d in enumerate(data):
        if d.get('fcs', 0) > 0:
            x = xp(i)
            L.append(f'  <line x1="{x:.1f}" y1="{MT}" x2="{x:.1f}" y2="{MB}" stroke="#eab308" stroke-width="0.8" opacity="0.5"/>')

    rr_pts = " ".join(f"{xp(i):.1f},{yp(min(d['rr'], 100)):.1f}" for i, d in enumerate(data))
    L.append(f'  <polyline points="{rr_pts}" fill="none" stroke="#b91c1c" stroke-width="1.2" opacity="0.6"/>')
    L.append(f'  <line x1="{MR + 8}" y1="{yp(0):.1f}" x2="{MR + 8}" y2="{yp(50):.1f}" stroke="#b91c1c" stroke-width="0.8" opacity="0.4"/>')
    rr_label = '重传率' if zh else 'Retransmit Rate'
    L.append(f'  <text x="{MR + 12}" y="{yp(25):.1f}" font-size="7" fill="#b91c1c" opacity="0.7" transform="rotate(-90,{MR + 12},{yp(25):.1f})">{rr_label}</text>')

    L.append(f'  <line x1="{ML}" y1="{MB}" x2="{MR}" y2="{MB}" stroke="#374151" stroke-width="1"/>')
    L.append(f'  <line x1="{ML}" y1="{MT}" x2="{ML}" y2="{MB}" stroke="#374151" stroke-width="1"/>')

    x_step = max(1, n // 12)
    for i in range(0, n, x_step):
        x = xp(i)
        sec = data[i]['sec']
        L.append(f'  <text x="{x:.1f}" y="{MB + 14}" text-anchor="middle" font-size="8.5" fill="#6b7280">{sec}s</text>')
    if (n - 1) % x_step != 0:
        x = xp(n - 1)
        sec = data[-1]['sec']
        L.append(f'  <text x="{x:.1f}" y="{MB + 14}" text-anchor="middle" font-size="8.5" fill="#6b7280">{sec}s</text>')

    time_label = '时间' if zh else 'Time'
    L.append(f'  <text x="{(ML + MR) // 2}" y="{MB + 28}" text-anchor="middle" font-size="9" fill="#9ca3af">{time_label}</text>')

    legend_y = MB + 46
    for i, (_, color, label) in enumerate(layers):
        x = ML + i * 140
        L.append(f'  <rect x="{x}" y="{legend_y - 7}" width="11" height="11" rx="2" fill="{color}" opacity="0.78"/>')
        L.append(f'  <text x="{x + 15}" y="{legend_y + 3}" font-size="8.5" fill="#374151">{label}</text>')

    avg_p = sum(d['payload'] for d in data) / n
    avg_r = sum(d['retransmit'] for d in data) / n
    avg_ct = sum(d['rts_cts'] for d in data) / n
    total_fcs = sum(d.get('fcs', 0) for d in data)
    dur = data[-1]['sec'] - data[0]['sec']
    if zh:
        summary = f'平均有效率 {avg_p:.1f}% | 重传 {avg_r:.1f}% | 竞争 {avg_ct:.1f}% | FCS错误 {total_fcs} | 时长 {dur}s'
    else:
        summary = f'Avg payload {avg_p:.1f}% | Retransmit {avg_r:.1f}% | Contention {avg_ct:.1f}% | FCS errors {total_fcs} | Duration {dur}s'
    L.append(f'  <text x="{ML}" y="{legend_y + 22}" font-size="8.5" fill="#6b7280">{summary}</text>')
    fcs_label = 'FCS错误' if zh else 'FCS Error'
    L.append(f'  <line x1="{MR - 140}" y1="{legend_y - 2}" x2="{MR - 120}" y2="{legend_y - 2}" stroke="#eab308" stroke-width="0.8" opacity="0.6"/>')
    L.append(f'  <text x="{MR - 116}" y="{legend_y + 2}" font-size="8" fill="#92400e">{fcs_label}</text>')
    L.append('</svg>')

    with open(output_path, 'w') as f:
        f.write('\n'.join(L))
    print(f"  Chart: {output_path}")

    import subprocess, shutil
    png_path = output_path.replace('.svg', '.png')
    if shutil.which('rsvg-convert'):
        try:
            subprocess.run(['rsvg-convert', '-w', '2400', output_path, '-o', png_path], check=True, capture_output=True)
            print(f"  PNG:   {png_path}")
        except Exception:
            pass


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='Hardware-level WiFi metrics from pcapng')
    ap.add_argument('pcapng', help='pcapng capture file')
    ap.add_argument('macs', nargs='*', help='Filter by MAC address(es)')
    ap.add_argument('--chart', metavar='SVG', help='Generate payload-ratio chart (SVG path)')
    args = ap.parse_args()

    path = args.pcapng
    formatted = []
    for m in (args.macs or []):
        if ':' not in m:
            m = ':'.join(m[i:i + 2] for i in range(0, len(m), 2))
        formatted.append(m.lower())

    results = analyze_hw_metrics(path, formatted)
    print_report(results, formatted)

    if args.chart:
        generate_payload_chart(results['sec_stats'], args.chart)
