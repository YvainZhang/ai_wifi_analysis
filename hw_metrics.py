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
    target_macs = set(target_macs or [])
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
    sec_stats = defaultdict(lambda: {
        'data': 0, 'ctrl': 0, 'mgmt': 0,
        'retransmit': 0, 'data_bytes': 0, 'total_bytes': 0,
        'sig_samples': defaultdict(list),  # mac -> [signals]
    })

    # Per-second signal per target MAC
    sec_signal = defaultdict(lambda: defaultdict(list))  # mac -> sec -> [signal]

    # Retry frame signal vs non-retry signal (to see if retransmits correlate with low signal)
    retry_sig = defaultdict(list)    # mac -> [signal of retry frames]
    normal_sig = defaultdict(list)   # mac -> [signal of normal frames]

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
        if sig is not None and addr2:
            for mac in [addr2_l, addr1_l]:
                if mac in target_macs or not target_macs:
                    sig_hist[mac][sig] += 1
                    sec_signal[mac][sec].append(sig)
                    sig_window[mac][sec // 5].append(sig)

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
        elif is_ctrl:
            s['ctrl'] += 1
        elif is_mgmt:
            s['mgmt'] += 1
        s['total_bytes'] += total_len
        if is_retry and is_data:
            s['retransmit'] += 1

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
        buckets = ['<64', '64-127', '128-255', '256-511', '512-1024', '1024-1500', '>1500']
        for b in buckets:
            c = sizes.get(b, 0)
            pct = c / total * 100 if total else 0
            bar = '█' * max(1, int(pct / 2))
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

    # 11. Summary diagnostics
    print("\n## 11. 硬件指标诊断总结")
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
        avg = statistics.mean(all_s)
        std = statistics.stdev(all_s) if len(all_s) > 1 else 0
        mn = min(hist.keys())
        mx = max(hist.keys())
        rng = mx - mn

        # Most frames at minimum
        min_pct = hist.get(mn, 0) / total * 100
        if min_pct > 90:
            issues.append(f"[!!] {mac}: {min_pct:.0f}% 的帧信号为最低值 {mn} dBm")
        elif min_pct > 70:
            issues.append(f"[!]  {mac}: {min_pct:.0f}% 的帧信号为最低值 {mn} dBm")

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


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 hw_metrics.py <pcapng> [mac1] [mac2] ...")
        sys.exit(1)

    path = sys.argv[1]
    targets = sys.argv[2:] if len(sys.argv) > 2 else []

    formatted = []
    for m in targets:
        if ':' not in m:
            m = ':'.join(m[i:i+2] for i in range(0, len(m), 2))
        formatted.append(m.lower())

    results = analyze_hw_metrics(path, formatted)
    print_report(results, formatted)
