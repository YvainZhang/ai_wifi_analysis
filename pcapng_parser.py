#!/usr/bin/env python3
"""
pcapng parser for 802.11 WiFi captures.
Pure Python, no external dependencies.

Parses pcapng files with radiotap headers and extracts:
- Frame statistics
- BA (Block Ack) management events
- Disconnect events (Deauth / Disassociation)
- Signal strength tracking
- Retransmission detection (sequence number gaps)
- Association / Authentication flow
"""

import struct
import os
import time as time_mod
from collections import defaultdict

# --- pcapng block types ---
SHB = 0x0A0D0D0A
IDB = 0x00000001
SPB = 0x00000003
EPB = 0x00000006

# --- 802.11 constants ---
MGMT = 0x0
CTRL = 0x1
DATA = 0x2
EXT = 0x3

ASSOC_REQ = 0x0
ASSOC_RESP = 0x1
REASSOC_REQ = 0x2
REASSOC_RESP = 0x3
PROBE_REQ = 0x4
PROBE_RESP = 0x5
BEACON = 0x8
ATIM = 0x9
DISASSOC = 0xA
AUTH = 0xB
DEAUTH = 0xC
ACTION = 0xD
ACTION_NO_ACK = 0xE

CAT_BA = 0x03
ADDBA_REQ = 0x0
ADDBA_RESP = 0x1
DELBA = 0x2

TYPE_NAMES = {MGMT: "Management", CTRL: "Control", DATA: "Data", EXT: "Extension"}
SUBTYPE_NAMES = {
    (MGMT, ASSOC_REQ): "Association Request",
    (MGMT, ASSOC_RESP): "Association Response",
    (MGMT, REASSOC_REQ): "Reassociation Request",
    (MGMT, REASSOC_RESP): "Reassociation Response",
    (MGMT, PROBE_REQ): "Probe Request",
    (MGMT, PROBE_RESP): "Probe Response",
    (MGMT, BEACON): "Beacon",
    (MGMT, DISASSOC): "Disassociation",
    (MGMT, AUTH): "Authentication",
    (MGMT, DEAUTH): "Deauthentication",
    (MGMT, ACTION): "Action",
    (MGMT, ACTION_NO_ACK): "Action No-Ack",
    (DATA, 0x0): "Data",
    (DATA, 0x1): "Data + CF-Ack",
    (DATA, 0x2): "Data + CF-Poll",
    (DATA, 0x3): "Data + CF-Ack+Poll",
    (DATA, 0x4): "Null",
    (DATA, 0x5): "CF-Ack (no data)",
    (DATA, 0x6): "CF-Poll (no data)",
    (DATA, 0x7): "CF-Ack+Poll (no data)",
    (DATA, 0x8): "QoS Data",
    (DATA, 0x9): "QoS Data + CF-Ack",
    (DATA, 0xA): "QoS Data + CF-Poll",
    (DATA, 0xB): "QoS Data + CF-Ack+Poll",
    (DATA, 0xC): "QoS Null",
    (DATA, 0xD): "Reserved",
    (DATA, 0xE): "QoS CF-Poll (no data)",
    (DATA, 0xF): "QoS CF-Ack+Poll (no data)",
    (CTRL, 0x8): "Block Ack Request",
    (CTRL, 0x9): "Block Ack",
    (CTRL, 0xA): "PS-Poll",
    (CTRL, 0xB): "RTS",
    (CTRL, 0xC): "CTS",
    (CTRL, 0xD): "ACK",
    (CTRL, 0xE): "CF-End",
    (CTRL, 0xF): "CF-End + CF-Ack",
}


def mac_str(b):
    return ':'.join('%02x' % x for x in b)


def subtype_name(ftype, fsub):
    return SUBTYPE_NAMES.get((ftype, fsub), "Unknown sub%d" % fsub)


# ============================================================
# pcapng reader
# ============================================================

class PcapngReader:
    """Iterate over packets in a pcapng file."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.file_size = os.path.getsize(filepath)
        self.interfaces = []
        self.packet_count = 0
        self._ts_resolutions = []  # per-interface, in units per second (1e6 or 1e9)

    def __iter__(self):
        with open(self.filepath, 'rb') as f:
            while True:
                hdr = f.read(8)
                if len(hdr) < 8:
                    return
                btype, blen = struct.unpack('<II', hdr)
                body = f.read(blen - 12)
                f.read(4)  # trailing length

                if btype == SHB:
                    pass
                elif btype == IDB:
                    self._parse_idb(body)
                elif btype == EPB:
                    pkt = self._parse_epb(body)
                    if pkt:
                        self.packet_count += 1
                        yield pkt
                elif btype == SPB:
                    pkt = self._parse_spb(body)
                    if pkt:
                        self.packet_count += 1
                        yield pkt

    def _parse_idb(self, body):
        link_type, snap_len = struct.unpack('<HI', body[:6])
        idx = len(self.interfaces)
        self.interfaces.append({'link_type': link_type, 'snap_len': snap_len})
        # Default: microseconds (10^-6)
        res = 1e6
        # Parse IDB options to find if_tsresol (option code 9)
        opt_off = 8  # after fixed fields (2 + 2 + 4 = 8, but only 6 used, pad to 8)
        while opt_off + 4 <= len(body):
            opt_code, opt_len = struct.unpack('<HH', body[opt_off:opt_off + 4])
            if opt_code == 0:  # end of options
                break
            if opt_code == 9 and opt_len >= 1:  # if_tsresol
                resol = body[opt_off + 4]
                if resol & 0x80:  # negative power of 10
                    res = 10 ** (resol & 0x7F)
                else:  # negative power of 2
                    res = 2 ** (resol & 0x7F)
            opt_off += 4 + ((opt_len + 3) & ~3)  # options are padded to 4-byte boundary
        self._ts_resolutions.append(res)

    def _parse_epb(self, body):
        if len(body) < 20:
            return None
        iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack('<IIIII', body[:20])
        if cap_len > 10 * 1024 * 1024:  # sanity: >10MB per packet is wrong
            return None
        pkt_data = body[20:20 + cap_len]

        ts_raw = (ts_high << 32) | ts_low
        if iface_id < len(self._ts_resolutions):
            ts_sec = ts_raw / self._ts_resolutions[iface_id]
        else:
            ts_sec = ts_raw / 1e6
        # Sanity check: if timestamp is in the far future, try nanosecond resolution
        now = time_mod.time()
        if ts_sec > now + 86400:
            ts_sec = ts_raw / 1e9

        return {
            'interface': iface_id,
            'timestamp': ts_sec,
            'cap_len': cap_len,
            'orig_len': orig_len,
            'data': pkt_data,
        }

    def _parse_spb(self, body):
        if len(body) < 4:
            return None
        orig_len = struct.unpack('<I', body[:4])[0]
        pkt_data = body[4:]
        return {
            'interface': 0,
            'timestamp': 0,
            'cap_len': len(pkt_data),
            'orig_len': orig_len,
            'data': pkt_data,
        }


# ============================================================
# Radiotap parser
# ============================================================

def parse_radiotap(raw):
    """Parse radiotap header. Returns (info_dict, remaining_bytes)."""
    if len(raw) < 8 or raw[0] != 0x00:
        return {}, raw

    _ver, _pad, hdr_len, present = struct.unpack('<BBHI', raw[:8])
    if hdr_len > len(raw) or hdr_len < 8:
        return {}, raw

    info = {}
    # Read all present-flag words
    flags_list = []
    off = 8
    while off <= hdr_len - 4:
        pf = struct.unpack('<I', raw[off:off + 4])[0]
        flags_list.append(pf)
        off += 4
        if not (pf & 0x80000000):
            break

    # Walk fields
    off = 8 + len(flags_list) * 4
    for pf in flags_list:
        if off >= hdr_len:
            break
        for bit in range(30):
            if not (pf & (1 << bit)):
                continue
            try:
                if bit == 0 and off + 8 <= hdr_len:  # TSFT
                    info['tsft'] = struct.unpack('<Q', raw[off:off + 8])[0]
                    off += 8
                elif bit == 1 and off + 1 <= hdr_len:  # Flags
                    info['flags'] = raw[off]
                    off += 1
                elif bit == 2 and off + 1 <= hdr_len:  # Rate (500kbps units)
                    info['rate'] = raw[off] * 0.5  # Mbps
                    off += 1
                elif bit == 3 and off + 4 <= hdr_len:  # Channel
                    freq, chflags = struct.unpack('<HH', raw[off:off + 4])
                    info['channel_freq'] = freq
                    info['channel'] = (freq - 2407) // 5 if freq < 3000 else (freq - 5000) // 5
                    off += 4
                elif bit == 4 and off + 2 <= hdr_len:  # FHSS
                    off += 2
                elif bit == 5 and off + 1 <= hdr_len:  # dBm signal
                    info['dbm_signal'] = struct.unpack('<b', raw[off:off + 1])[0]
                    off += 1
                elif bit == 6 and off + 1 <= hdr_len:  # dBm noise
                    info['dbm_noise'] = struct.unpack('<b', raw[off:off + 1])[0]
                    off += 1
                elif bit == 7 and off + 2 <= hdr_len:  # Lock quality
                    off += 2
                elif bit == 8 and off + 2 <= hdr_len:  # TX attenuation
                    off += 2
                elif bit == 9 and off + 2 <= hdr_len:  # TX dBm
                    off += 2
                elif bit == 10 and off + 2 <= hdr_len:  # Antenna
                    info['antenna'] = raw[off]
                    off += 2
                elif bit == 11 and off + 2 <= hdr_len:  # RX flags
                    info['rx_flags'] = struct.unpack('<H', raw[off:off + 2])[0]
                    off += 2
                elif bit == 12 and off + 4 <= hdr_len:  # TX flags
                    off += 4
                elif bit == 13 and off + 1 <= hdr_len:  # RSSI
                    info['rssi'] = struct.unpack('<b', raw[off:off + 1])[0]
                    off += 1
                elif bit == 14 and off + 4 <= hdr_len:  # Channel+
                    freq, chflags, channel = struct.unpack('<IHHI', raw[off:off + 8])
                    info['channel_freq'] = freq
                    off += 8
                elif bit >= 15:
                    # Unknown / vendor field — can't determine size, abort
                    break
            except struct.error:
                break

    return info, raw[hdr_len:]


# ============================================================
# 802.11 frame parser
# ============================================================

def parse_frame(data):
    """Parse 802.11 MAC header. Returns info dict."""
    if len(data) < 2:
        return None

    fc = struct.unpack('<H', data[:2])[0]
    ftype = (fc >> 2) & 0x3
    fsub = (fc >> 4) & 0xF
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)
    retry = bool(fc & 0x0800)

    info = {
        'fc': fc,
        'type': ftype,
        'subtype': fsub,
        'type_name': TYPE_NAMES.get(ftype, "Unknown"),
        'subtype_name': subtype_name(ftype, fsub),
        'to_ds': to_ds,
        'from_ds': from_ds,
        'retry': retry,
    }

    if ftype == MGMT:
        if len(data) >= 24:
            info['duration'] = struct.unpack('<H', data[2:4])[0]
            info['addr1'] = mac_str(data[4:10])
            info['addr2'] = mac_str(data[10:16])
            info['addr3'] = mac_str(data[16:22])
            sc = struct.unpack('<H', data[22:24])[0]
            info['seq_num'] = (sc >> 4) & 0xFFF
            info['frag_num'] = sc & 0xF
            info['body'] = data[24:]
        if fsub == ACTION and len(data) > 26:
            _parse_action(info)
        elif fsub == DEAUTH and len(data) >= 26:
            info['reason_code'] = struct.unpack('<H', data[24:26])[0]
        elif fsub == DISASSOC and len(data) >= 26:
            info['reason_code'] = struct.unpack('<H', data[24:26])[0]
        elif fsub == AUTH and len(data) >= 28:
            info['auth_algo'] = struct.unpack('<H', data[24:26])[0]
            info['auth_seq'] = struct.unpack('<H', data[26:28])[0]
            if len(data) >= 30:
                info['auth_status'] = struct.unpack('<H', data[28:30])[0]
        elif fsub == ASSOC_RESP and len(data) >= 28:
            info['capab'] = struct.unpack('<H', data[24:26])[0]
            info['status_code'] = struct.unpack('<H', data[26:28])[0]
            if len(data) >= 30:
                info['assoc_id'] = struct.unpack('<H', data[28:30])[0] & 0x3FFF
        elif fsub == BEACON and len(data) >= 36:
            info['beacon_ts'] = struct.unpack('<Q', data[24:32])[0]
            info['beacon_interval'] = struct.unpack('<H', data[32:34])[0]

    elif ftype == DATA:
        hdr_len = 24
        if fsub >= 0x8:  # QoS
            hdr_len = 26
        if len(data) >= hdr_len:
            info['duration'] = struct.unpack('<H', data[2:4])[0]
            info['addr1'] = mac_str(data[4:10])
            info['addr2'] = mac_str(data[10:16])
            info['addr3'] = mac_str(data[16:22])
            sc = struct.unpack('<H', data[22:24])[0]
            info['seq_num'] = (sc >> 4) & 0xFFF
            info['frag_num'] = sc & 0xF
            if fsub >= 0x8:
                info['qos_tid'] = data[24] & 0x0F

    elif ftype == CTRL:
        if fsub == 0x9 and len(data) >= 16:  # Block Ack
            info['duration'] = struct.unpack('<H', data[2:4])[0]
            info['ra'] = mac_str(data[4:10])
            info['ta'] = mac_str(data[10:16])
        elif fsub == 0x8 and len(data) >= 16:  # BAR
            info['ra'] = mac_str(data[4:10])
            info['ta'] = mac_str(data[10:16])
        elif fsub in (0xB, 0xC, 0xD):  # RTS/CTS/ACK
            info['ra'] = mac_str(data[4:10])
            if fsub == 0xB and len(data) >= 10:
                info['ta'] = mac_str(data[10:16])

    return info


def _parse_action(info):
    body = info.get('body', b'')
    if len(body) < 2:
        return
    info['action_category'] = body[0]
    info['action_code'] = body[1]

    if body[0] != CAT_BA:
        return

    if body[1] == ADDBA_REQ and len(body) >= 9:
        dialog = body[2]
        ba_param = struct.unpack('>H', body[3:5])[0]
        timeout = struct.unpack('<H', body[5:7])[0]
        seq_ctrl = struct.unpack('<H', body[7:9])[0]
        info['ba'] = {
            'action': 'ADDBA Request',
            'dialog': dialog,
            'tid': (ba_param >> 2) & 0xF,
            'bufsize': ba_param & 0x3FF,
            'amsdu': bool(ba_param & 0x1),
            'policy': 'Immediate' if (ba_param >> 1) & 1 else 'Delayed',
            'timeout': timeout,
            'seq_start': (seq_ctrl >> 4) & 0xFFF,
        }

    elif body[1] == ADDBA_RESP and len(body) >= 9:
        dialog = body[2]
        status = struct.unpack('<H', body[3:5])[0]
        ba_param = struct.unpack('>H', body[5:7])[0]
        timeout = struct.unpack('<H', body[7:9])[0]
        info['ba'] = {
            'action': 'ADDBA Response',
            'dialog': dialog,
            'status': status,
            'status_ok': status == 0,
            'tid': (ba_param >> 2) & 0xF,
            'bufsize': ba_param & 0x3FF,
            'timeout': timeout,
        }

    elif body[1] == DELBA and len(body) >= 6:
        ba_param = struct.unpack('>H', body[2:4])[0]
        reason = struct.unpack('<H', body[4:6])[0]
        info['ba'] = {
            'action': 'DELBA',
            'tid': (ba_param >> 12) & 0xF,
            'initiator': 'Originator' if (ba_param >> 11) & 1 else 'Recipient',
            'reason': reason,
        }


# ============================================================
# DHCP parser (deep inspection of data frames)
# ============================================================

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_NAK = 5
DHCP_ACK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8

DHCP_MSG_NAMES = {
    1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline',
    5: 'NAK', 6: 'ACK', 7: 'Release', 8: 'Inform',
}


def _parse_dhcp_from_frame(wifi_info, wifi_raw):
    """
    Try to extract DHCP info from a data frame.
    Returns dict or None.
    wifi_raw is the raw 802.11 frame data (after radiotap).
    """
    fc = struct.unpack('<H', wifi_raw[:2])[0]
    ftype = (fc >> 2) & 0x3
    fsub = (fc >> 4) & 0xF
    protected = bool(fc & 0x4000)

    # Only QoS Data or plain Data
    if ftype != DATA or fsub not in (0x0, 0x8):
        return None
    if protected:
        return None

    hdr_len = 26 if fsub >= 0x8 else 24
    if len(wifi_raw) < hdr_len + 8:
        return None

    payload = wifi_raw[hdr_len:]

    # LLC/SNAP header: AA AA 03 00 00 00 xx xx (ethertype)
    if len(payload) < 8:
        return None
    if payload[0] != 0xAA or payload[1] != 0xAA or payload[2] != 0x03:
        return None

    ethertype = struct.unpack('>H', payload[6:8])[0]
    if ethertype != 0x0800:  # Not IPv4
        return None

    ip_data = payload[8:]
    if len(ip_data) < 20:
        return None

    # IPv4 header
    ihl = (ip_data[0] & 0x0F) * 4
    proto = ip_data[9]
    if proto != 17:  # Not UDP
        return None
    if len(ip_data) < ihl + 8:
        return None

    udp_data = ip_data[ihl:]
    src_port, dst_port = struct.unpack('>HH', udp_data[:4])

    # DHCP uses ports 67 (server) and 68 (client)
    if src_port not in (67, 68) or dst_port not in (67, 68):
        return None

    dhcp_data = udp_data[8:]
    if len(dhcp_data) < 240:  # DHCP fixed part is 236 bytes + 4 magic
        return None

    # Check DHCP magic cookie at offset 236
    magic = struct.unpack('>I', dhcp_data[236:240])[0]
    if magic != 0x63825363:
        return None

    # Parse DHCP options to find Message Type (option 53)
    op = dhcp_data[236 + 4:]  # after magic cookie
    msg_type = None
    requested_ip = None
    server_id = None
    i = 0
    while i < len(op) - 1:
        tag = op[i]
        if tag == 0:  # Padding
            i += 1
            continue
        if tag == 255:  # End
            break
        if i + 1 >= len(op):
            break
        opt_len = op[i + 1]
        if i + 2 + opt_len > len(op):
            break
        opt_val = op[i + 2:i + 2 + opt_len]

        if tag == 53 and opt_len >= 1:  # Message Type
            msg_type = opt_val[0]
        elif tag == 50 and opt_len >= 4:  # Requested IP Address
            requested_ip = '%d.%d.%d.%d' % tuple(opt_val[:4])
        elif tag == 54 and opt_len >= 4:  # Server Identifier
            server_id = '%d.%d.%d.%d' % tuple(opt_val[:4])
        elif tag == 12 and opt_len >= 1:  # Host Name
            try:
                hostname = opt_val.decode('ascii', errors='replace')
            except Exception:
                hostname = ''
        i += 2 + opt_len

    if msg_type is None:
        return None

    # Extract client MAC from DHCP chaddr field (offset 28, 16 bytes)
    client_mac = mac_str(dhcp_data[28:34])

    # Determine actual source/dest based on to_ds/from_ds
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)
    addr1 = wifi_info.get('addr1', '')
    addr2 = wifi_info.get('addr2', '')
    addr3 = wifi_info.get('addr3', '')

    if from_ds and not to_ds:
        # Frame from AP: SA=addr3, DA=addr1
        src_mac = addr3
        dst_mac = addr1
    elif to_ds and not from_ds:
        # Frame to AP: SA=addr2, DA=addr3
        src_mac = addr2
        dst_mac = addr3
    else:
        src_mac = addr2
        dst_mac = addr1

    result = {
        'msg_type': msg_type,
        'msg_name': DHCP_MSG_NAMES.get(msg_type, 'Unknown(%d)' % msg_type),
        'src_mac': src_mac,
        'dst_mac': dst_mac,
        'client_mac': client_mac,
    }
    if requested_ip:
        result['requested_ip'] = requested_ip
    if server_id:
        result['server_id'] = server_id

    return result


# ============================================================
# High-level: parse full capture
# ============================================================

def parse_capture(filepath, mac_filter=None, time_from=None, time_to=None):
    """
    Parse a pcapng file and return structured results.

    Returns dict with keys:
        meta, frame_stats, ba_events, disconnect_events, assoc_events,
        signal_data, retransmit_stats, data_gap_events
    """
    reader = PcapngReader(filepath)
    frame_stats = defaultdict(int)
    ba_events = []
    disconnect_events = []
    assoc_events = []
    dhcp_events = []
    signal_data = defaultdict(list)
    seq_tracker = defaultdict(lambda: -1)  # (mac, tid) -> last seq
    retransmit_stats = defaultdict(int)
    data_timestamps = defaultdict(list)  # mac -> [timestamps]
    first_ts = None
    last_ts = None
    total = 0
    filtered = 0
    mac_set = set()

    if mac_filter:
        mac_set = {m.lower() for m in mac_filter}

    for pkt in reader:
        ts = pkt['timestamp']
        if first_ts is None:
            first_ts = ts
        last_ts = ts

        # Time filter
        if time_from is not None and ts < first_ts + time_from:
            continue
        if time_to is not None and ts > first_ts + time_to:
            break

        raw = pkt['data']
        rtap, wifi_data = parse_radiotap(raw)

        wifi = parse_frame(wifi_data)
        if wifi is None:
            continue

        total += 1

        # MAC filter
        addr1 = wifi.get('addr1', '')
        addr2 = wifi.get('addr2', '')
        ra = wifi.get('ra', '')
        ta = wifi.get('ta', '')

        if mac_set:
            all_macs = {addr1.lower(), addr2.lower(), ra.lower(), ta.lower()}
            if not all_macs & mac_set:
                filtered += 1
                continue

        rel_ts = ts - first_ts if first_ts else 0

        # Frame stats
        key = '%s/%s' % (wifi['type_name'], wifi['subtype_name'])
        frame_stats[key] += 1
        frame_stats[wifi['type_name']] += 1

        # Signal
        if 'dbm_signal' in rtap and addr2:
            signal_data[addr2].append((rel_ts, rtap['dbm_signal']))

        # Sequence tracking for retransmit detection
        if 'seq_num' in wifi and addr2 and wifi.get('retry'):
            retransmit_stats[addr2] += 1

        # Data flow tracking
        if wifi['type'] == DATA and addr2:
            data_timestamps[addr2].append(rel_ts)

        # DHCP deep inspection
        if wifi['type'] == DATA:
            dhcp = _parse_dhcp_from_frame(wifi, wifi_data)
            if dhcp:
                dhcp['time'] = rel_ts
                dhcp_events.append(dhcp)

        # BA events
        if wifi['type'] == MGMT and wifi['subtype'] == ACTION and 'ba' in wifi:
            ba_events.append({
                'time': rel_ts,
                'src': addr2,
                'dst': addr1,
                'ba': wifi['ba'],
            })

        # Disconnect events
        if wifi['type'] == MGMT and wifi['subtype'] in (DEAUTH, DISASSOC):
            disconnect_events.append({
                'time': rel_ts,
                'type': wifi['subtype_name'],
                'src': addr2,
                'dst': addr1,
                'reason': wifi.get('reason_code', -1),
            })

        # Association events
        if wifi['type'] == MGMT and wifi['subtype'] in (ASSOC_REQ, ASSOC_RESP, REASSOC_REQ, REASSOC_RESP, AUTH):
            evt = {
                'time': rel_ts,
                'type': wifi['subtype_name'],
                'src': addr2,
                'dst': addr1,
            }
            if 'status_code' in wifi:
                evt['status'] = wifi['status_code']
            if 'auth_status' in wifi:
                evt['status'] = wifi['auth_status']
            if 'assoc_id' in wifi:
                evt['aid'] = wifi['assoc_id']
            assoc_events.append(evt)

    duration = (last_ts - first_ts) if (first_ts and last_ts) else 0

    return {
        'meta': {
            'filepath': filepath,
            'file_size_mb': reader.file_size / 1024 / 1024,
            'total_packets': total,
            'filtered_packets': filtered,
            'reader_total': reader.packet_count,
            'duration': duration,
            'first_ts': first_ts,
            'interfaces': reader.interfaces,
        },
        'frame_stats': dict(frame_stats),
        'ba_events': ba_events,
        'disconnect_events': disconnect_events,
        'assoc_events': assoc_events,
        'dhcp_events': dhcp_events,
        'signal_data': dict(signal_data),
        'retransmit_stats': dict(retransmit_stats),
        'data_timestamps': dict(data_timestamps),
    }
