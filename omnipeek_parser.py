#!/usr/bin/env python3
"""
OmniPeek/AiroPeek .pkt file parser.
Extracts raw 802.11 frames and DHCP messages with timestamps.

File format (reverse-engineered):
  - Top-level blocks: 'ver', 'sess', 'pkts' — each: tag(4) + content_len(uint32) + content
  - Inside 'pkts': alternating ad(0xAD000000)-delimited records:
      Even-indexed ad: metadata TLVs  [tag(u16 LE) + val(4 bytes) each]
      Odd-indexed ad:  802.11 frame data
    Metadata TLVs:
      tag 0x0001: timestamp low (uint32)
      tag 0x0002: timestamp high (uint32)
      tag 0x0006: signal percentage (int32)
      tag 0x0007: signal dBm (int32)
      tag 0x0008: noise percentage (int32)
      tag 0x0009: noise dBm (int32)
    End of metadata: tag 0x0015 + 0x00000000 + 0xFFFF + ad marker
"""

import struct
import os
from bisect import bisect_left, bisect_right, insort
from collections import defaultdict
from pcapng_parser import (
    parse_frame, _parse_dhcp_from_frame, _parse_tcp_from_frame,
    _record_tcp_event, DATA,
    mac_str, TYPE_NAMES, subtype_name,
    DHCP_MSG_NAMES,
)

AD_MARKER = b'\xad\x00\x00\x00'
DHCP_MAGIC = b'\x63\x82\x53\x63'


def _find_ad_positions(data):
    """Find all ad marker positions in data."""
    positions = []
    pos = 0
    while True:
        idx = data.find(AD_MARKER, pos)
        if idx == -1:
            break
        positions.append(idx)
        pos = idx + 1
    return positions


def _parse_metadata(data, meta_start, meta_end):
    """Parse TLV metadata from the region between two ad markers."""
    result = {}
    pos = meta_start + 4  # skip ad marker
    while pos + 6 <= meta_end:
        tag = struct.unpack('<H', data[pos:pos + 2])[0]
        val = data[pos + 2:pos + 6]
        if tag == 0x0001:
            result['ts_low'] = struct.unpack('<I', val)[0]
        elif tag == 0x0002:
            result['ts_high'] = struct.unpack('<I', val)[0]
        elif tag == 0x0006:
            result['signal_percent'] = struct.unpack('<i', val)[0]
        elif tag == 0x0007:
            result['signal'] = struct.unpack('<i', val)[0]
        elif tag == 0x0008:
            result['noise_percent'] = struct.unpack('<i', val)[0]
        elif tag == 0x0009:
            result['noise'] = struct.unpack('<i', val)[0]
        elif tag == 0x0015:
            break  # end of metadata
        pos += 6
    return result


def _metadata_is_valid(data, meta_start, meta_end):
    """Return whether a marker-delimited region looks like metadata.

    Frame payloads can contain the AD marker by coincidence. Requiring a
    complete metadata terminator and at least one timestamp field prevents
    those payload markers from shifting record alignment.
    """
    if meta_end <= meta_start + 4:
        return False

    pos = meta_start + 4
    has_timestamp = False
    while pos + 6 <= meta_end:
        tag = struct.unpack('<H', data[pos:pos + 2])[0]
        if tag == 0x0015:
            return has_timestamp
        if tag in (0x0001, 0x0002):
            has_timestamp = True
        pos += 6
    return False


def _iter_records(data, ad_positions):
    """Yield ``(frame_start, frame_end, metadata)`` for valid records."""
    meta_index = 0
    while meta_index + 1 < len(ad_positions):
        meta_start = ad_positions[meta_index]
        frame_marker = ad_positions[meta_index + 1]
        if not _metadata_is_valid(data, meta_start, frame_marker):
            meta_index += 1
            continue

        frame_start = frame_marker + 4
        next_meta_index = meta_index + 2
        while next_meta_index + 1 < len(ad_positions):
            next_meta = ad_positions[next_meta_index]
            next_frame_marker = ad_positions[next_meta_index + 1]
            if _metadata_is_valid(data, next_meta, next_frame_marker):
                frame_end = next_meta
                frame_data = data[frame_start:frame_end]
                if len(frame_data) >= 10 and parse_frame(frame_data) is not None:
                    yield frame_start, frame_end, _parse_metadata(
                        data, meta_start, frame_marker)
                    meta_index = next_meta_index
                    break
            next_meta_index += 1
        else:
            # The final frame has no following metadata marker and runs to
            # EOF.  It is still a valid record when it parses cleanly.
            frame_data = data[frame_start:]
            if len(frame_data) >= 10 and parse_frame(frame_data) is not None:
                yield frame_start, len(data), _parse_metadata(
                    data, meta_start, frame_marker)
            meta_index += 1


def _metadata_timestamp_seconds(meta):
    """Convert OmniPeek's nanosecond FILETIME to Unix seconds."""
    if 'ts_low' not in meta and 'ts_high' not in meta:
        return None
    raw = (meta.get('ts_high', 0) << 32) | meta.get('ts_low', 0)
    if raw == 0:
        return None
    return raw / 1e9 - 11644473600


def parse_omnipeek(filepath, mac_filter=None, time_from=None, time_to=None):
    """
    Parse OmniPeek .pkt file.
    Returns dict compatible with pcapng_parser.parse_capture().
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    file_size = len(data)
    ad_positions = _find_ad_positions(data)

    if len(ad_positions) < 2:
        return _empty_result(filepath, file_size)

    # Recover records by validating metadata boundaries rather than relying on
    # marker parity; an AD marker may legitimately occur inside frame bytes.
    frame_stats = defaultdict(int)
    ba_events = []
    disconnect_events = []
    assoc_events = []
    dhcp_events = []
    signal_data = defaultdict(list)
    retransmit_stats = defaultdict(int)
    data_timestamps = defaultdict(list)
    ctrl_stats = defaultdict(int)
    tid_frames = defaultdict(int)
    tid_retransmit = defaultdict(int)
    implicit_retransmit = defaultdict(int)
    seq_tracker = {}
    tcp_stats = {'packets': 0, 'retransmissions': 0, 'flows': {}}
    tcp_seen_segments = set()
    filtered = 0
    mac_set = {m.lower() for m in (mac_filter or [])}
    offset_times = []

    # Timestamps are normalized to the first valid packet timestamp.
    first_ts = None
    last_rel_ts = 0.0
    record_count = 0

    for frame_start, frame_end, meta in _iter_records(data, ad_positions):
        record_count += 1
        frame_data = data[frame_start:frame_end]
        wifi = parse_frame(frame_data)
        timestamp = _metadata_timestamp_seconds(meta)
        if timestamp is not None and first_ts is None:
            first_ts = timestamp
        if timestamp is not None and first_ts is not None:
            rel_ts = max(0.0, timestamp - first_ts)
        else:
            rel_ts = last_rel_ts
        last_rel_ts = max(last_rel_ts, rel_ts)
        offset_times.append((frame_start, rel_ts))

        if time_from is not None and rel_ts < time_from:
            filtered += 1
            continue
        if time_to is not None and rel_ts > time_to:
            break

        addr1 = wifi.get('addr1', '')
        addr2 = wifi.get('addr2', '')
        ra = wifi.get('ra', '')
        ta = wifi.get('ta', '')

        if mac_set:
            all_macs = {addr1.lower(), addr2.lower(), ra.lower(), ta.lower()}
            if not all_macs & mac_set:
                filtered += 1
                continue

        # Frame stats
        sub_name = wifi.get('subtype_name', 'sub%d' % wifi.get('subtype', 0))
        key = '%s/%s' % (wifi['type_name'], sub_name)
        frame_stats[key] += 1
        frame_stats[wifi['type_name']] += 1

        # Signal
        if 'signal' in meta and addr2:
            signal_data[addr2].append((rel_ts, meta['signal']))

        # Retransmit
        if wifi.get('retry') and addr2:
            retransmit_stats[addr2] += 1

        if wifi['type'] == 1:
            ctrl_names = {0xB: 'RTS', 0xC: 'CTS', 0xD: 'ACK', 0x8: 'BAR', 0x9: 'BA'}
            if wifi['subtype'] in ctrl_names:
                ctrl_stats[ctrl_names[wifi['subtype']]] += 1

        tid = wifi.get('qos_tid')
        if tid is not None:
            tid_frames[tid] += 1
            if wifi.get('retry'):
                tid_retransmit[tid] += 1

        if 'seq_num' in wifi and addr2 and wifi['type'] == DATA:
            track_key = (addr2, tid)
            last_sn = seq_tracker.get(track_key)
            cur_sn = wifi['seq_num']
            if last_sn is not None and not wifi.get('retry'):
                delta = (cur_sn - last_sn) % 4096
                if 1 < delta < 2048:
                    implicit_retransmit[addr2] += 1
            seq_tracker[track_key] = cur_sn

        # BA events
        if wifi['type'] == 0 and wifi.get('subtype') == 0xD and 'ba' in wifi:
            ba_events.append({
                'time': rel_ts, 'src': addr2, 'dst': addr1, 'ba': wifi['ba'],
            })

        # Disconnect
        if wifi['type'] == 0 and wifi.get('subtype') in (0xC, 0xA):
            disconnect_events.append({
                'time': rel_ts, 'type': wifi['subtype_name'],
                'src': addr2, 'dst': addr1, 'reason': wifi.get('reason_code', -1),
            })

        # Association
        if wifi['type'] == 0 and wifi.get('subtype') in (0x0, 0x1, 0x2, 0x3, 0xB):
            evt = {'time': rel_ts, 'type': wifi['subtype_name'], 'src': addr2, 'dst': addr1}
            if 'status_code' in wifi:
                evt['status'] = wifi['status_code']
            assoc_events.append(evt)

        # DHCP from data frames
        if wifi['type'] == DATA:
            if addr2:
                data_timestamps[addr2].append(rel_ts)
            dhcp = _parse_dhcp_from_frame(wifi, frame_data)
            if dhcp:
                dhcp['time'] = rel_ts
                dhcp['offset'] = frame_start
                dhcp_events.append(dhcp)
            tcp = _parse_tcp_from_frame(wifi, frame_data)
            if tcp:
                tcp['time'] = rel_ts
                tcp['link_retry'] = bool(wifi.get('retry'))
                _record_tcp_event(tcp_stats, tcp_seen_segments, tcp)

    # Also scan raw data for DHCP (handles cases where frame parsing misses data frames)
    raw_dhcp = _scan_raw_dhcp(data, offset_times)
    if time_from is not None:
        raw_dhcp = [e for e in raw_dhcp if e['time'] >= time_from]
    if time_to is not None:
        raw_dhcp = [e for e in raw_dhcp if e['time'] <= time_to]
    if mac_set:
        raw_dhcp = [e for e in raw_dhcp if e.get('client_mac', '').lower() in mac_set]
    # Merge raw DHCP into dhcp_events (dedup by offset proximity)
    _merge_dhcp_events(dhcp_events, raw_dhcp)

    total_frames = sum(frame_stats.get(t, 0) for t in TYPE_NAMES.values())

    return {
        'meta': {
            'filepath': filepath,
            'file_size_mb': file_size / 1024 / 1024,
            'total_packets': total_frames,
            'filtered_packets': filtered,
            'reader_total': record_count,
            'duration': last_rel_ts,
            'first_ts': first_ts,
            'interfaces': [{'link_type': 105, 'snap_len': 65535}],
            'format': 'OmniPeek/AiroPeek .pkt',
        },
        'frame_stats': dict(frame_stats),
        'ctrl_stats': dict(ctrl_stats),
        'tid_frames': dict(tid_frames),
        'tid_retransmit': dict(tid_retransmit),
        'fcs_errors': 0,
        'implicit_retransmit': dict(implicit_retransmit),
        'ba_events': ba_events,
        'disconnect_events': disconnect_events,
        'assoc_events': assoc_events,
        'dhcp_events': dhcp_events,
        'signal_data': dict(signal_data),
        'retransmit_stats': dict(retransmit_stats),
        'tcp_stats': tcp_stats,
        'data_timestamps': dict(data_timestamps),
    }


def _scan_raw_dhcp(data, offset_times):
    """
    Scan raw file data for DHCP messages by searching for the magic cookie.
    This catches DHCP even when frame extraction misses data frames.
    """
    dhcp_events = []
    offsets = [item[0] for item in offset_times]
    pos = 0
    while True:
        idx = data.find(DHCP_MAGIC, pos)
        if idx == -1:
            break
        pos = idx + 1

        bootp_start = idx - 236
        if bootp_start < 0:
            continue

        op = data[bootp_start]
        if op not in (1, 2):
            continue
        htype = data[bootp_start + 1]
        hlen = data[bootp_start + 2]
        if htype != 1 or hlen != 6:
            continue

        xid = struct.unpack('>I', data[bootp_start + 4:bootp_start + 8])[0]
        chaddr = mac_str(data[bootp_start + 28:bootp_start + 34])

        # Parse DHCP options
        opt_start = idx + 4
        msg_type = None
        server_id = None
        requested_ip = None
        hostname = None
        j = opt_start
        while j + 1 < len(data):
            tag = data[j]
            if tag == 0:
                j += 1
                continue
            if tag == 255:
                break
            opt_len = data[j + 1]
            opt_end = j + 2 + opt_len
            if opt_end > len(data):
                break
            opt_val = data[j + 2:opt_end]
            if tag == 53 and opt_len >= 1:
                msg_type = opt_val[0]
            elif tag == 54 and opt_len >= 4:
                server_id = '%d.%d.%d.%d' % tuple(opt_val[:4])
            elif tag == 50 and opt_len >= 4:
                requested_ip = '%d.%d.%d.%d' % tuple(opt_val[:4])
            elif tag == 12 and opt_len >= 1:
                hostname = opt_val.decode('ascii', errors='replace')
            j = opt_end

        if msg_type is None:
            continue

        time_idx = bisect_right(offsets, bootp_start) - 1
        event_time = offset_times[time_idx][1] if time_idx >= 0 else 0.0

        dhcp_events.append({
            'time': event_time,
            'msg_type': msg_type,
            'msg_name': DHCP_MSG_NAMES.get(msg_type, 'Unknown(%d)' % msg_type),
            'src_mac': '',
            'dst_mac': '',
            'client_mac': chaddr,
            'xid': xid,
            'op': 'Request' if op == 1 else 'Reply',
            'offset': bootp_start,
        })
        if server_id:
            dhcp_events[-1]['server_id'] = server_id
        if requested_ip:
            dhcp_events[-1]['requested_ip'] = requested_ip
        if hostname:
            dhcp_events[-1]['hostname'] = hostname

    return dhcp_events


def _merge_dhcp_events(existing, new_events):
    """Merge raw-scanned DHCP events into existing list, avoiding duplicates."""
    existing_offsets = []
    for e in existing:
        # Approximate offset from time
        offset = e.get('offset', -1)
        if offset >= 0:
            insort(existing_offsets, offset)

    for e in new_events:
        offset = e.get('offset', 0)
        index = bisect_left(existing_offsets, offset)
        nearby = []
        if index:
            nearby.append(existing_offsets[index - 1])
        if index < len(existing_offsets):
            nearby.append(existing_offsets[index])
        if not any(abs(offset - eo) < 300 for eo in nearby):
            existing.append(e)
            insort(existing_offsets, offset)

    existing.sort(key=lambda event: event.get('time', 0))


def _empty_result(filepath, file_size):
    return {
        'meta': {
            'filepath': filepath,
            'file_size_mb': file_size / 1024 / 1024,
            'total_packets': 0, 'filtered_packets': 0, 'reader_total': 0,
            'duration': 0, 'first_ts': None,
            'interfaces': [{'link_type': 105, 'snap_len': 65535}],
            'format': 'OmniPeek/AiroPeek .pkt',
        },
        'frame_stats': {}, 'ctrl_stats': {}, 'tid_frames': {},
        'tid_retransmit': {}, 'fcs_errors': 0, 'implicit_retransmit': {},
        'ba_events': [], 'disconnect_events': [],
        'assoc_events': [], 'dhcp_events': [], 'signal_data': {},
        'retransmit_stats': {}, 'tcp_stats': {'packets': 0, 'retransmissions': 0, 'flows': {}},
        'data_timestamps': {},
    }
