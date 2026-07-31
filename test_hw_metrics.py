#!/usr/bin/env python3
import contextlib
import io
import os
import struct
import tempfile
import unittest

from hw_metrics import analyze_hw_metrics, print_report


TRANSMITTER = '00:11:22:33:44:55'
BROADCAST = 'ff:ff:ff:ff:ff:ff'


def mac_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(':'))


def pcapng_block(block_type, body):
    block_len = 12 + len(body)
    return struct.pack('<II', block_type, block_len) + body + struct.pack('<I', block_len)


def build_minimal_pcapng(packet):
    section = pcapng_block(
        0x0A0D0D0A,
        struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1),
    )
    interface = pcapng_block(1, struct.pack('<HHI', 127, 0, 65535))
    padding = b'\x00' * ((-len(packet)) % 4)
    packet_body = (
        struct.pack('<IIIII', 0, 0, 1_000_000, len(packet), len(packet))
        + packet
        + padding
    )
    return section + interface + pcapng_block(6, packet_body)


def build_packet(flags=0):
    present = (1 << 1) | (1 << 5)
    radiotap = struct.pack('<BBHIBb', 0, 0, 10, present, flags, -42)

    wifi = struct.pack('<HH', 0x0008, 0)
    wifi += mac_bytes(BROADCAST)
    wifi += mac_bytes(TRANSMITTER)
    wifi += mac_bytes(TRANSMITTER)
    wifi += struct.pack('<H', 0)
    wifi += b'\x00' * (600 - len(wifi))
    return radiotap + wifi


class HardwareMetricsTest(unittest.TestCase):
    def analyze_packet(self, flags=0):
        capture = build_minimal_pcapng(build_packet(flags=flags))
        with tempfile.NamedTemporaryFile(suffix='.pcapng', delete=False) as tmp:
            tmp.write(capture)
            path = tmp.name
        try:
            return analyze_hw_metrics(path)
        finally:
            os.unlink(path)

    def render_report(self, results):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            print_report(results, [])
        return output.getvalue()

    def test_default_report_uses_transmitters_and_correct_size_bucket(self):
        results = self.analyze_packet()

        self.assertEqual(dict(results['sig_hist'][TRANSMITTER]), {-42: 1})
        self.assertNotIn(BROADCAST, results['sig_hist'])
        self.assertEqual(
            dict(results['frame_sizes'][TRANSMITTER]),
            {'512-1023': 1},
        )

        report = self.render_report(results)
        self.assertIn(TRANSMITTER, report)
        self.assertNotIn(BROADCAST, report)
        self.assertIn('512-1023 B', report)
        self.assertNotIn('512-1024 B', report)
        empty_bucket = next(
            line for line in report.splitlines() if '<64 B' in line
        )
        self.assertNotIn('█', empty_bucket)
        self.assertNotIn('的帧信号为最低值', report)
        self.assertIn('未发现硬件层异常', report)

    def test_fcs_rate_uses_each_frame_once(self):
        results = self.analyze_packet(flags=0x40)

        report = self.render_report(results)

        self.assertIn('FCS 错误帧: 1 (错误率 100.00%', report)


if __name__ == '__main__':
    unittest.main()
