#!/usr/bin/env python3
"""
pcapng parser for 802.11 WiFi captures.
Pure Python, no external dependencies.

Parses pcapng files with radiotap headers and extracts:
- Frame statistics
- BA (Block Ack) management events
- Disconnect events (Deauth / Disassociation)
- Signal strength tracking
- 802.11 MAC retry detection
- TCP/IP retransmission detection for plain IPv4/TCP payloads
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


def ip_str(b):
    return '%d.%d.%d.%d' % tuple(b)


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
                if blen < 12 or blen % 4 or blen > self.file_size:
                    return
                body = f.read(blen - 12)
                trailer = f.read(4)
                if len(body) != blen - 12 or len(trailer) != 4:
                    return
                if struct.unpack('<I', trailer)[0] != blen:
                    return

                if btype == SHB:
                    # Interface IDs and timestamp resolutions are scoped to
                    # one section and restart at zero after every SHB.
                    self.interfaces = []
                    self._ts_resolutions = []
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
        if len(body) < 8:
            return
        link_type, _reserved, snap_len = struct.unpack('<HHI', body[:8])
        self.interfaces.append({'link_type': link_type, 'snap_len': snap_len})
        # Default: microseconds (10^-6)
        res = 1e6
        # Parse IDB options to find if_tsresol (option code 9)
        opt_off = 8  # after fixed fields (2 + 2 + 4 = 8, but only 6 used, pad to 8)
        while opt_off + 4 <= len(body):
            opt_code, opt_len = struct.unpack('<HH', body[opt_off:opt_off + 4])
            if opt_code == 0:  # end of options
                break
            if opt_off + 4 + opt_len > len(body):
                break
            if opt_code == 9 and opt_len >= 1:  # if_tsresol
                resol = body[opt_off + 4]
                if resol & 0x80:  # negative power of 2
                    res = 2 ** (resol & 0x7F)
                else:  # negative power of 10
                    res = 10 ** resol
            opt_off += 4 + ((opt_len + 3) & ~3)  # options are padded to 4-byte boundary
        self._ts_resolutions.append(res)

    def _parse_epb(self, body):
        if len(body) < 20:
            return None
        iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack('<IIIII', body[:20])
        if cap_len > 10 * 1024 * 1024:  # sanity: >10MB per packet is wrong
            return None
        if 20 + cap_len > len(body):
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

    _ver, _pad, hdr_len, _present = struct.unpack('<BBHI', raw[:8])
    if hdr_len > len(raw) or hdr_len < 8:
        return {}, raw

    info = {}
    # Read all present-flag words
    flags_list = [_present]
    off = 8
    while flags_list[-1] & 0x80000000:
        if off > hdr_len - 4:
            return {}, raw
        pf = struct.unpack('<I', raw[off:off + 4])[0]
        flags_list.append(pf)
        off += 4

    # Fields are aligned relative to the beginning of the radiotap header.
    # This parser intentionally stops before bit 14, where captures commonly
    # start carrying fields whose sizes vary by radiotap revision/vendor.
    off = 8 + (len(flags_list) - 1) * 4
    present0 = flags_list[0] if flags_list else 0
    field_layout = {
        0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4),
        4: (2, 2), 5: (1, 1), 6: (1, 1), 7: (2, 2),
        8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1),
        12: (1, 1), 13: (1, 1),
    }
    for bit in range(14):
        if not (present0 & (1 << bit)):
            continue
        align, size = field_layout[bit]
        off = (off + align - 1) & ~(align - 1)
        if off + size > hdr_len:
            break

        if bit == 0:
            info['tsft'] = struct.unpack_from('<Q', raw, off)[0]
        elif bit == 1:
            info['flags'] = raw[off]
        elif bit == 2:
            info['rate'] = raw[off] * 0.5
        elif bit == 3:
            freq, _chflags = struct.unpack_from('<HH', raw, off)
            info['channel_freq'] = freq
            info['channel'] = (freq - 2407) // 5 if freq < 3000 else (freq - 5000) // 5
        elif bit == 5:
            info['dbm_signal'] = struct.unpack_from('<b', raw, off)[0]
        elif bit == 6:
            info['dbm_noise'] = struct.unpack_from('<b', raw, off)[0]
        elif bit == 10:
            info['dbm_tx_power'] = struct.unpack_from('<b', raw, off)[0]
        elif bit == 11:
            info['antenna'] = raw[off]
        elif bit == 12:
            info['db_signal'] = raw[off]
        elif bit == 13:
            info['db_noise'] = raw[off]
        off += size

    return info, raw[hdr_len:]


# ============================================================
# 802.11 frame parser
# ============================================================

def _data_header_layout(fc):
    """Return ``(header_length, qos_control_offset)`` for a data frame."""
    fsub = (fc >> 4) & 0xF
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)
    qos = fsub >= 0x8
    header_len = 24
    if to_ds and from_ds:
        header_len += 6
    qos_offset = None
    if qos:
        qos_offset = header_len
        header_len += 2
        # Order/HT-Control is present on QoS data when the order bit is set.
        if fc & 0x8000:
            header_len += 4
    return header_len, qos_offset

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
        hdr_len, qos_offset = _data_header_layout(fc)
        if len(data) >= hdr_len:
            info['duration'] = struct.unpack('<H', data[2:4])[0]
            info['addr1'] = mac_str(data[4:10])
            info['addr2'] = mac_str(data[10:16])
            info['addr3'] = mac_str(data[16:22])
            if to_ds and from_ds:
                info['addr4'] = mac_str(data[24:30])
            sc = struct.unpack('<H', data[22:24])[0]
            info['seq_num'] = (sc >> 4) & 0xFFF
            info['frag_num'] = sc & 0xF
            if qos_offset is not None:
                info['qos_tid'] = data[qos_offset] & 0x0F

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
        ba_param = struct.unpack('<H', body[3:5])[0]
        timeout = struct.unpack('<H', body[5:7])[0]
        seq_ctrl = struct.unpack('<H', body[7:9])[0]
        info['ba'] = {
            'action': 'ADDBA Request',
            'dialog': dialog,
            'tid': (ba_param >> 2) & 0xF,
            'bufsize': (ba_param >> 6) & 0x3FF,
            'amsdu': bool(ba_param & 0x1),
            'policy': 'Immediate' if (ba_param >> 1) & 1 else 'Delayed',
            'timeout': timeout,
            'seq_start': (seq_ctrl >> 4) & 0xFFF,
        }

    elif body[1] == ADDBA_RESP and len(body) >= 9:
        dialog = body[2]
        status = struct.unpack('<H', body[3:5])[0]
        ba_param = struct.unpack('<H', body[5:7])[0]
        timeout = struct.unpack('<H', body[7:9])[0]
        info['ba'] = {
            'action': 'ADDBA Response',
            'dialog': dialog,
            'status': status,
            'status_ok': status == 0,
            'tid': (ba_param >> 2) & 0xF,
            'bufsize': (ba_param >> 6) & 0x3FF,
            'timeout': timeout,
        }

    elif body[1] == DELBA and len(body) >= 6:
        ba_param = struct.unpack('<H', body[2:4])[0]
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
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8

DHCP_MSG_NAMES = {
    1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline',
    5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform',
}


def _parse_dhcp_from_frame(wifi_info, wifi_raw):
    """
    Try to extract DHCP info from a data frame.
    Returns dict or None.
    wifi_raw is the raw 802.11 frame data (after radiotap).
    """
    if len(wifi_raw) < 2:
        return None
    fc = struct.unpack('<H', wifi_raw[:2])[0]
    ftype = (fc >> 2) & 0x3
    fsub = (fc >> 4) & 0xF
    protected = bool(fc & 0x4000)

    # Only QoS Data or plain Data
    if ftype != DATA or fsub not in (0x0, 0x8):
        return None
    if protected:
        return None

    hdr_len, _ = _data_header_layout(fc)
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
    hostname = None
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
    addr4 = wifi_info.get('addr4', '')

    if from_ds and not to_ds:
        # Frame from AP: SA=addr3, DA=addr1
        src_mac = addr3
        dst_mac = addr1
    elif to_ds and not from_ds:
        # Frame to AP: SA=addr2, DA=addr3
        src_mac = addr2
        dst_mac = addr3
    elif to_ds and from_ds:
        src_mac = addr4 or addr2
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
        'xid': struct.unpack('>I', dhcp_data[4:8])[0],
        'op': 'Request' if dhcp_data[0] == 1 else 'Reply',
    }
    if requested_ip:
        result['requested_ip'] = requested_ip
    if server_id:
        result['server_id'] = server_id
    if hostname:
        result['hostname'] = hostname

    return result


def _data_payload_from_frame(wifi_raw):
    """Return 802.11 data payload after the MAC header, or None."""
    if len(wifi_raw) < 2:
        return None

    fc = struct.unpack('<H', wifi_raw[:2])[0]
    ftype = (fc >> 2) & 0x3
    fsub = (fc >> 4) & 0xF
    protected = bool(fc & 0x4000)
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)

    if ftype != DATA or fsub not in (0x0, 0x8):
        return None
    if protected:
        return None

    hdr_len, _ = _data_header_layout(fc)
    if len(wifi_raw) < hdr_len + 8:
        return None
    return wifi_raw[hdr_len:]


def _parse_tcp_from_frame(wifi_info, wifi_raw):
    """
    Extract IPv4/TCP metadata from a plain 802.11 data frame.
    Returns dict or None. Encrypted/protected frames cannot be decoded.
    """
    payload = _data_payload_from_frame(wifi_raw)
    if payload is None:
        return None

    # LLC/SNAP header: AA AA 03 00 00 00 xx xx (ethertype)
    if len(payload) < 8:
        return None
    if payload[0] != 0xAA or payload[1] != 0xAA or payload[2] != 0x03:
        return None

    ethertype = struct.unpack('>H', payload[6:8])[0]
    if ethertype != 0x0800:
        return None

    ip_data = payload[8:]
    if len(ip_data) < 20:
        return None
    version = ip_data[0] >> 4
    ihl = (ip_data[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(ip_data) < ihl:
        return None

    total_len = struct.unpack('>H', ip_data[2:4])[0]
    proto = ip_data[9]
    if proto != 6:
        return None
    if total_len < ihl + 20:
        return None
    if len(ip_data) < total_len:
        return None

    tcp_data = ip_data[ihl:total_len]
    if len(tcp_data) < 20:
        return None
    tcp_hdr_len = (tcp_data[12] >> 4) * 4
    if tcp_hdr_len < 20 or len(tcp_data) < tcp_hdr_len:
        return None

    src_port, dst_port = struct.unpack('>HH', tcp_data[:4])
    seq, ack = struct.unpack('>II', tcp_data[4:12])
    payload_len = max(0, total_len - ihl - tcp_hdr_len)

    return {
        'src_mac': wifi_info.get('addr2', ''),
        'dst_mac': wifi_info.get('addr1', ''),
        'src_ip': ip_str(ip_data[12:16]),
        'dst_ip': ip_str(ip_data[16:20]),
        'src_port': src_port,
        'dst_port': dst_port,
        'seq': seq,
        'ack': ack,
        'flags': tcp_data[13],
        'payload_len': payload_len,
    }


def _tcp_flow_key(tcp):
    return '%s:%d -> %s:%d' % (
        tcp['src_ip'], tcp['src_port'], tcp['dst_ip'], tcp['dst_port'])


def _record_tcp_event(tcp_stats, seen_segments, tcp, max_events=50):
    """
    Record a TCP packet and count conservative retransmission candidates.
    A retransmission is counted when the same directional flow repeats the
    same sequence number and payload length for a non-empty payload.
    """
    flow = _tcp_flow_key(tcp)
    flows = tcp_stats.setdefault('flows', {})
    flow_stats = flows.setdefault(flow, {
        'packets': 0,
        'payload_bytes': 0,
        'retransmissions': 0,
        'events': [],
    })

    tcp_stats['packets'] = tcp_stats.get('packets', 0) + 1
    tcp_stats.setdefault('retransmissions', 0)
    flow_stats['packets'] += 1
    flow_stats['payload_bytes'] += tcp.get('payload_len', 0)

    if tcp.get('payload_len', 0) <= 0 or tcp.get('link_retry'):
        return False

    segment = (flow, tcp['seq'], tcp['payload_len'])
    if segment not in seen_segments:
        seen_segments.add(segment)
        return False

    tcp_stats['retransmissions'] += 1
    flow_stats['retransmissions'] += 1
    event = {
        'time': tcp.get('time', 0),
        'flow': flow,
        'seq': tcp['seq'],
        'payload_len': tcp['payload_len'],
    }
    if len(flow_stats['events']) < max_events:
        flow_stats['events'].append(event)
    return True


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
    seq_tracker = {}
    retransmit_stats = defaultdict(int)
    data_timestamps = defaultdict(list)
    ctrl_stats = defaultdict(int)
    tid_frames = defaultdict(int)
    tid_retransmit = defaultdict(int)
    fcs_errors = 0
    implicit_retransmit = defaultdict(int)
    tcp_stats = {'packets': 0, 'retransmissions': 0, 'flows': {}}
    tcp_seen_segments = set()
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

        interface_id = pkt['interface']
        if interface_id >= len(reader.interfaces):
            continue

        link_type = reader.interfaces[interface_id]['link_type']
        raw = pkt['data']
        if link_type == 127:
            rtap, wifi_data = parse_radiotap(raw)
        elif link_type == 105:
            rtap, wifi_data = {}, raw
        else:
            continue

        wifi = parse_frame(wifi_data)
        if wifi is None:
            continue

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

        total += 1
        rel_ts = ts - first_ts if first_ts is not None else 0

        # Frame stats
        key = '%s/%s' % (wifi['type_name'], wifi['subtype_name'])
        frame_stats[key] += 1
        frame_stats[wifi['type_name']] += 1

        # Control frame subtype tracking
        if wifi['type'] == 1:
            for sn, sn_name in [(0xB, 'RTS'), (0xC, 'CTS'), (0xD, 'ACK'),
                                (0x8, 'BAR'), (0x9, 'BA')]:
                if wifi['subtype'] == sn:
                    ctrl_stats[sn_name] += 1
                    break

        # TID distribution (QoS Data frames)
        tid = wifi.get('qos_tid')
        if tid is not None:
            tid_frames[tid] += 1

        # Radiotap Flags bit 6 marks a frame with a bad FCS.
        if rtap.get('flags', 0) & 0x40:
            fcs_errors += 1
            continue

        # Signal
        if 'dbm_signal' in rtap and addr2:
            signal_data[addr2].append((rel_ts, rtap['dbm_signal']))

        # Sequence tracking for retransmit detection
        if wifi.get('retry') and 'seq_num' in wifi and addr2:
            retransmit_stats[addr2] += 1
            if tid is not None:
                tid_retransmit[tid] += 1

        # Implicit retransmit / seq gap detection
        if 'seq_num' in wifi and addr2 and wifi['type'] == DATA:
            track_key = (addr2, tid)
            last_sn = seq_tracker.get(track_key)
            cur_sn = wifi['seq_num']
            if last_sn is not None and not wifi.get('retry'):
                delta = (cur_sn - last_sn) % 4096
                if 1 < delta < 2048:
                    implicit_retransmit[addr2] += 1
            seq_tracker[track_key] = cur_sn

        # Data flow tracking
        if wifi['type'] == DATA and addr2:
            data_timestamps[addr2].append(rel_ts)

        # DHCP deep inspection
        if wifi['type'] == DATA:
            dhcp = _parse_dhcp_from_frame(wifi, wifi_data)
            if dhcp:
                dhcp['time'] = rel_ts
                dhcp_events.append(dhcp)

            tcp = _parse_tcp_from_frame(wifi, wifi_data)
            if tcp:
                tcp['time'] = rel_ts
                tcp['link_retry'] = bool(wifi.get('retry'))
                _record_tcp_event(tcp_stats, tcp_seen_segments, tcp)

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

    duration = (last_ts - first_ts) if (first_ts is not None and last_ts is not None) else 0

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
            'format': 'pcapng',
        },
        'frame_stats': dict(frame_stats),
        'ctrl_stats': dict(ctrl_stats),
        'tid_frames': dict(tid_frames),
        'tid_retransmit': dict(tid_retransmit),
        'fcs_errors': fcs_errors,
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
