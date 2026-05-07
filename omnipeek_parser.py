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
      tag 0x0006: signal (int32)
      tag 0x0007: noise (int32)
    End of metadata: tag 0x0015 + 0x00000000 + 0xFFFF + ad marker
"""

import struct
import os
from collections import defaultdict
from pcapng_parser import (
    parse_frame, _parse_dhcp_from_frame, DATA,
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
            result['signal'] = struct.unpack('<i', val)[0]
        elif tag == 0x0007:
            result['noise'] = struct.unpack('<i', val)[0]
        elif tag == 0x0015:
            break  # end of metadata
        pos += 6
    return result


def parse_omnipeek(filepath):
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

    # Odd-indexed ad markers = frame data; even-indexed = metadata
    # Extract frames with their metadata
    frame_stats = defaultdict(int)
    ba_events = []
    disconnect_events = []
    assoc_events = []
    dhcp_events = []
    signal_data = defaultdict(list)
    retransmit_stats = defaultdict(int)

    # Timestamps: normalize to 0-based using first frame's ts_low
    first_ts = None

    for i in range(1, len(ad_positions), 2):
        frame_start = ad_positions[i] + 4
        if i + 1 < len(ad_positions):
            frame_end = ad_positions[i + 1]
        else:
            frame_end = file_size

        if frame_end - frame_start < 4:
            continue

        frame_data = data[frame_start:frame_end]
        wifi = parse_frame(frame_data)
        if wifi is None:
            continue

        # Extract timestamp from preceding metadata (even-indexed ad)
        meta = _parse_metadata(data, ad_positions[i - 1], ad_positions[i])
        ts_raw = meta.get('ts_low', 0)

        if first_ts is None:
            first_ts = frame_start
        rel_ts = frame_start - first_ts

        addr1 = wifi.get('addr1', '')
        addr2 = wifi.get('addr2', '')
        addr3 = wifi.get('addr3', '')

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
            dhcp = _parse_dhcp_from_frame(wifi, frame_data)
            if dhcp:
                dhcp['time'] = rel_ts
                dhcp_events.append(dhcp)

    # Also scan raw data for DHCP (handles cases where frame parsing misses data frames)
    raw_dhcp = _scan_raw_dhcp(data, ad_positions, first_ts)
    # Merge raw DHCP into dhcp_events (dedup by offset proximity)
    _merge_dhcp_events(dhcp_events, raw_dhcp)

    total_frames = sum(frame_stats.get(t, 0) for t in TYPE_NAMES.values())
    last_ts = ts_raw - first_ts if first_ts else 0

    return {
        'meta': {
            'filepath': filepath,
            'file_size_mb': file_size / 1024 / 1024,
            'total_packets': total_frames,
            'filtered_packets': 0,
            'reader_total': (len(ad_positions) - 1) // 2,
            'duration': last_ts,
            'first_ts': first_ts,
            'interfaces': [{'link_type': 105, 'snap_len': 65535}],
            'format': 'OmniPeek/AiroPeek .pkt',
        },
        'frame_stats': dict(frame_stats),
        'ba_events': ba_events,
        'disconnect_events': disconnect_events,
        'assoc_events': assoc_events,
        'dhcp_events': dhcp_events,
        'signal_data': dict(signal_data),
        'retransmit_stats': dict(retransmit_stats),
        'data_timestamps': {},
    }


def _scan_raw_dhcp(data, ad_positions, first_ts):
    """
    Scan raw file data for DHCP messages by searching for the magic cookie.
    This catches DHCP even when frame extraction misses data frames.
    """
    dhcp_events = []
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
        while j < len(data) - 2:
            tag = data[j]
            if tag == 0:
                j += 1
                continue
            if tag == 255:
                break
            opt_len = data[j + 1]
            opt_val = data[j + 2:j + 2 + opt_len]
            if tag == 53 and opt_len >= 1:
                msg_type = opt_val[0]
            elif tag == 54 and opt_len >= 4:
                server_id = '%d.%d.%d.%d' % tuple(opt_val[:4])
            elif tag == 50 and opt_len >= 4:
                requested_ip = '%d.%d.%d.%d' % tuple(opt_val[:4])
            elif tag == 12:
                hostname = opt_val.decode('ascii', errors='replace')
            j += 2 + opt_len

        if msg_type is None:
            continue

        # Use file offset as relative timestamp (proportional to real time)
        # This is approximate but gives correct ordering and rough timing
        approx_ts = bootp_start

        dhcp_events.append({
            'time': approx_ts,
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
    existing_offsets = set()
    for e in existing:
        # Approximate offset from time
        existing_offsets.add(e.get('offset', -1))

    for e in new_events:
        offset = e.get('offset', 0)
        is_dup = False
        for eo in existing_offsets:
            if abs(offset - eo) < 300:
                is_dup = True
                break
        if not is_dup:
            existing.append(e)


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
        'frame_stats': {}, 'ba_events': [], 'disconnect_events': [],
        'assoc_events': [], 'dhcp_events': [], 'signal_data': {},
        'retransmit_stats': {}, 'data_timestamps': {},
    }
