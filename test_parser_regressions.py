#!/usr/bin/env python3
import os
import struct
import tempfile
import unittest

from analyze import apply_event_filter, detect_capture_format, generate_report
from omnipeek_parser import AD_MARKER, _metadata_timestamp_seconds, parse_omnipeek
from pcapng_parser import (
    PcapngReader,
    _parse_dhcp_from_frame,
    parse_capture,
    parse_frame,
    parse_radiotap,
)


def mac_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(':'))


def build_wifi_data_frame(payload):
    header = struct.pack('<HH', 0x0008, 0)
    header += mac_bytes('66:77:88:99:aa:bb')
    header += mac_bytes('00:11:22:33:44:55')
    header += mac_bytes('66:77:88:99:aa:bb')
    header += struct.pack('<H', 0x0010)
    return header + payload


def build_dhcp_frame():
    dhcp = bytearray(240)
    dhcp[0:3] = b'\x01\x01\x06'
    dhcp[4:8] = struct.pack('>I', 0x12345678)
    dhcp[28:34] = mac_bytes('00:11:22:33:44:55')
    dhcp[236:240] = b'\x63\x82\x53\x63'
    options = b'\x35\x01\x01\x0c\x04test\xff'
    udp_len = 8 + len(dhcp) + len(options)
    udp = struct.pack('>HHHH', 68, 67, udp_len, 0) + dhcp + options
    ip_len = 20 + len(udp)
    ip = struct.pack(
        '>BBHHHBBH4s4s',
        0x45, 0, ip_len, 0, 0, 64, 17, 0,
        bytes((0, 0, 0, 0)), bytes((255, 255, 255, 255)),
    )
    llc = b'\xaa\xaa\x03\x00\x00\x00\x08\x00'
    return build_wifi_data_frame(llc + ip + udp)


def build_omnipeek_metadata(timestamp):
    low = timestamp & 0xFFFFFFFF
    high = timestamp >> 32
    return (
        struct.pack('<HI', 0x0001, low)
        + struct.pack('<HI', 0x0002, high)
        + struct.pack('<Hi', 0x0007, -55)
        + struct.pack('<HI', 0x0015, 0)
    )


def pcapng_block(block_type, body):
    block_len = 12 + len(body)
    return struct.pack('<II', block_type, block_len) + body + struct.pack('<I', block_len)


def build_minimal_pcapng(packet, timestamp=1_000_000):
    shb = pcapng_block(
        0x0A0D0D0A,
        struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1),
    )
    idb_body = struct.pack('<HHI', 127, 0, 65535)
    idb_body += struct.pack('<HHB3x', 9, 1, 6) + struct.pack('<HH', 0, 0)
    idb = pcapng_block(1, idb_body)
    padding = b'\x00' * ((-len(packet)) % 4)
    epb_body = struct.pack(
        '<IIIII', 0, timestamp >> 32, timestamp & 0xFFFFFFFF,
        len(packet), len(packet),
    ) + packet + padding
    return shb + idb + pcapng_block(6, epb_body)


class TimestampResolutionTest(unittest.TestCase):
    def _reader_with_resolution(self, value):
        reader = PcapngReader.__new__(PcapngReader)
        reader.interfaces = []
        reader._ts_resolutions = []
        fixed = struct.pack('<HHI', 127, 0, 65535)
        option = struct.pack('<HHB3x', 9, 1, value) + struct.pack('<HH', 0, 0)
        reader._parse_idb(fixed + option)
        return reader._ts_resolutions[0]

    def test_decimal_timestamp_resolution(self):
        self.assertEqual(self._reader_with_resolution(6), 1_000_000)

    def test_binary_timestamp_resolution(self):
        self.assertEqual(self._reader_with_resolution(0x8A), 1024)


class CaptureFormatTest(unittest.TestCase):
    def test_classic_pcap_is_rejected_explicitly(self):
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp.write(b'\xd4\xc3\xb2\xa1' + b'\x00' * 20)
            path = tmp.name
        try:
            with self.assertRaisesRegex(ValueError, 'classic pcap'):
                detect_capture_format(path)
        finally:
            os.unlink(path)


class RadiotapTest(unittest.TestCase):
    def test_common_fields_are_aligned_and_mapped(self):
        present = sum(1 << bit for bit in (0, 1, 2, 3, 5, 6, 10, 11, 12, 13, 14))
        fields = struct.pack('<QBBHHbbbbbb', 123, 0x10, 12, 2412, 0, -42, -92, 15, 2, 50, 8)
        header = struct.pack('<BBHI', 0, 0, 8 + len(fields), present) + fields
        info, remaining = parse_radiotap(header + b'\x08\x00')

        self.assertEqual(info['tsft'], 123)
        self.assertEqual(info['rate'], 6.0)
        self.assertEqual(info['channel'], 1)
        self.assertEqual(info['dbm_signal'], -42)
        self.assertEqual(info['dbm_noise'], -92)
        self.assertEqual(info['dbm_tx_power'], 15)
        self.assertEqual(info['antenna'], 2)
        self.assertNotIn('rx_flags', info)
        self.assertEqual(remaining, b'\x08\x00')

    def test_pcapng_end_to_end_bad_fcs_and_schema(self):
        wifi = build_wifi_data_frame(b'')
        radiotap = struct.pack('<BBHI', 0, 0, 9, 1 << 1) + b'\x40'
        capture = build_minimal_pcapng(radiotap + wifi)
        with tempfile.NamedTemporaryFile(suffix='.pcapng', delete=False) as tmp:
            tmp.write(capture)
            path = tmp.name
        try:
            result = parse_capture(path)
        finally:
            os.unlink(path)

        self.assertEqual(result['meta']['format'], 'pcapng')
        self.assertEqual(result['meta']['first_ts'], 1.0)
        self.assertEqual(result['fcs_errors'], 1)
        self.assertEqual(
            set(result),
            {
                'meta', 'frame_stats', 'ctrl_stats', 'tid_frames',
                'tid_retransmit', 'fcs_errors', 'implicit_retransmit',
                'ba_events', 'disconnect_events', 'assoc_events',
                'dhcp_events', 'signal_data', 'retransmit_stats',
                'tcp_stats', 'data_timestamps',
            },
        )


class DhcpSchemaTest(unittest.TestCase):
    def test_dhcp_fields_match_report_contract(self):
        frame = build_dhcp_frame()
        event = _parse_dhcp_from_frame(parse_frame(frame), frame)

        self.assertEqual(event['xid'], 0x12345678)
        self.assertEqual(event['op'], 'Request')
        self.assertEqual(event['hostname'], 'test')

        event['time'] = 0.25
        result = {
            'meta': {
                'filepath': 'sample.pcapng', 'file_size_mb': 0.1,
                'reader_total': 1, 'total_packets': 1, 'duration': 1.0,
                'interfaces': [],
            },
            'frame_stats': {'Data': 1},
            'ba_events': [], 'disconnect_events': [], 'assoc_events': [],
            'dhcp_events': [event], 'signal_data': {}, 'retransmit_stats': {},
            'tcp_stats': {'packets': 0, 'retransmissions': 0, 'flows': {}},
        }
        report = generate_report(result)
        self.assertIn('xid=0x12345678', report)
        self.assertIn('主机=test', report)


class OmnipeekTest(unittest.TestCase):
    def test_filetime_conversion_and_time_filter(self):
        base = 13_300_000_000_000_000_000
        self.assertAlmostEqual(
            _metadata_timestamp_seconds({'ts_low': base & 0xFFFFFFFF, 'ts_high': base >> 32}),
            base / 1e9 - 11644473600,
        )

        frame = build_wifi_data_frame(b'')
        data = (
            AD_MARKER + build_omnipeek_metadata(base)
            + AD_MARKER + frame
            + AD_MARKER + build_omnipeek_metadata(base + 1_000_000_000)
            + AD_MARKER + frame
        )
        with tempfile.NamedTemporaryFile(suffix='.pkt', delete=False) as tmp:
            tmp.write(data)
            path = tmp.name
        try:
            result = parse_omnipeek(path, time_from=0.5)
        finally:
            os.unlink(path)

        self.assertAlmostEqual(result['meta']['duration'], 1.0)
        self.assertEqual(result['meta']['total_packets'], 1)
        self.assertEqual(result['meta']['filtered_packets'], 1)
        self.assertIn('ctrl_stats', result)
        self.assertIn('tid_frames', result)
        self.assertIn('implicit_retransmit', result)

    def test_signal_event_filter_hides_management_events(self):
        result = {
            'ba_events': [{'ba': {'tid': 0}}],
            'disconnect_events': [{}],
            'assoc_events': [{}],
        }
        apply_event_filter(result, event_type='signal')
        self.assertEqual(result['ba_events'], [])
        self.assertEqual(result['disconnect_events'], [])
        self.assertEqual(result['assoc_events'], [])


if __name__ == '__main__':
    unittest.main()
