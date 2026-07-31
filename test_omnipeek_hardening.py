#!/usr/bin/env python3
import os
import struct
import tempfile
import unittest

from omnipeek_parser import (
    AD_MARKER,
    _scan_raw_dhcp,
    parse_omnipeek,
)
from pcapng_parser import _data_payload_from_frame, parse_frame
from wifi_analyzer import is_local_endpoint
from test_parser_regressions import (
    build_omnipeek_metadata,
    build_wifi_data_frame,
)


class OmniPeekHardeningTest(unittest.TestCase):
    def test_wds_qos_ht_control_layout(self):
        fc = 0x0088 | 0x0300 | 0x8000  # QoS data, ToDS+FromDS, HT control
        macs = [bytes.fromhex(x) for x in (
            '001122334455', '66778899aabb', 'ccddeeff0011', '123456789abc')]
        header = struct.pack('<HH', fc, 0) + b''.join(macs[:3]) + struct.pack('<H', 7 << 4)
        header += macs[3]
        header += struct.pack('<H', 0x0005) + b'\x00' * 4
        payload = b'\xaa\xaa\x03\x00\x00\x00\x08\x00hello'
        frame = header + payload
        info = parse_frame(frame)
        self.assertEqual(info['addr4'], '12:34:56:78:9a:bc')
        self.assertEqual(info['qos_tid'], 5)
        self.assertEqual(_data_payload_from_frame(frame), payload)

    def test_local_endpoint_does_not_require_api_key(self):
        self.assertTrue(is_local_endpoint('http://localhost:11434'))
        self.assertTrue(is_local_endpoint('http://127.0.0.1:8000/v1'))
        self.assertFalse(is_local_endpoint('https://api.openai.com'))

    def test_marker_inside_frame_payload_does_not_shift_records(self):
        base = 13_300_000_000_000_000_000
        embedded_marker = AD_MARKER + b'payload'
        frame_one = build_wifi_data_frame(embedded_marker)
        frame_two = build_wifi_data_frame(b'')
        data = (
            AD_MARKER + build_omnipeek_metadata(base)
            + AD_MARKER + frame_one
            + AD_MARKER + build_omnipeek_metadata(base + 1_000_000_000)
            + AD_MARKER + frame_two
        )

        with tempfile.NamedTemporaryFile(suffix='.pkt', delete=False) as tmp:
            tmp.write(data)
            path = tmp.name
        try:
            result = parse_omnipeek(path)
        finally:
            os.unlink(path)

        self.assertEqual(result['meta']['reader_total'], 2)
        self.assertEqual(result['meta']['total_packets'], 2)
        self.assertEqual(result['meta']['duration'], 1.0)

    def test_truncated_raw_dhcp_option_is_ignored(self):
        payload = bytearray(240)
        payload[0] = 2
        payload[1] = 1
        payload[2] = 6
        payload[236:240] = b'\x63\x82\x53\x63'
        # Option 54 declares four bytes but only one is present.
        payload.extend(bytes((54, 4, 192)))

        self.assertEqual(_scan_raw_dhcp(bytes(payload), []), [])


if __name__ == '__main__':
    unittest.main()
