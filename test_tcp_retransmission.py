#!/usr/bin/env python3
import struct
import unittest

from pcapng_parser import _parse_tcp_from_frame, _record_tcp_event
from analyze import generate_report


def mac_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(':'))


def ip_bytes(ip):
    return bytes(int(part) for part in ip.split('.'))


def build_tcp_wifi_frame(seq, payload=b'hello'):
    fc = 0x0008  # Data frame, no DS bits, not protected
    wifi_header = struct.pack('<HH', fc, 0)
    wifi_header += mac_bytes('66:77:88:99:aa:bb')  # addr1 / DA
    wifi_header += mac_bytes('00:11:22:33:44:55')  # addr2 / SA
    wifi_header += mac_bytes('66:77:88:99:aa:bb')  # addr3 / BSSID
    wifi_header += struct.pack('<H', 0x0010)

    tcp_header = struct.pack(
        '>HHIIHHHH',
        12345,       # src port
        5201,        # dst port
        seq,
        0,           # ack
        0x5018,      # data offset 5, PSH+ACK
        65535,
        0,
        0,
    )
    total_len = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        '>BBHHHBBH4s4s',
        0x45,
        0,
        total_len,
        0,
        0,
        64,
        6,           # TCP
        0,
        ip_bytes('192.168.1.10'),
        ip_bytes('192.168.1.1'),
    )
    llc_snap = b'\xaa\xaa\x03\x00\x00\x00\x08\x00'
    return wifi_header + llc_snap + ip_header + tcp_header + payload


class TcpRetransmissionTest(unittest.TestCase):
    def test_parse_tcp_from_plain_ipv4_data_frame(self):
        wifi = {
            'type': 2,
            'subtype': 0,
            'addr1': '66:77:88:99:aa:bb',
            'addr2': '00:11:22:33:44:55',
            'addr3': '66:77:88:99:aa:bb',
        }

        tcp = _parse_tcp_from_frame(wifi, build_tcp_wifi_frame(seq=1000))

        self.assertIsNotNone(tcp)
        self.assertEqual(tcp['src_ip'], '192.168.1.10')
        self.assertEqual(tcp['dst_ip'], '192.168.1.1')
        self.assertEqual(tcp['src_port'], 12345)
        self.assertEqual(tcp['dst_port'], 5201)
        self.assertEqual(tcp['seq'], 1000)
        self.assertEqual(tcp['payload_len'], 5)

    def test_record_tcp_event_counts_repeated_payload_seq_as_retransmission(self):
        stats = {'packets': 0, 'retransmissions': 0, 'flows': {}}
        seen = set()
        first = _parse_tcp_from_frame({}, build_tcp_wifi_frame(seq=1000))
        second = _parse_tcp_from_frame({}, build_tcp_wifi_frame(seq=1000))
        first['time'] = 1.0
        second['time'] = 1.5

        _record_tcp_event(stats, seen, first)
        _record_tcp_event(stats, seen, second)

        flow = '192.168.1.10:12345 -> 192.168.1.1:5201'
        self.assertEqual(stats['packets'], 2)
        self.assertEqual(stats['retransmissions'], 1)
        self.assertEqual(stats['flows'][flow]['packets'], 2)
        self.assertEqual(stats['flows'][flow]['retransmissions'], 1)
        self.assertEqual(stats['flows'][flow]['events'][0]['time'], 1.5)

    def test_report_explains_when_plain_tcp_payload_is_unavailable(self):
        result = {
            'meta': {
                'filepath': 'sample.pcapng',
                'file_size_mb': 1.0,
                'reader_total': 1,
                'total_packets': 1,
                'duration': 1.0,
                'interfaces': [],
            },
            'frame_stats': {'Data': 1, 'Data/QoS Data': 1},
            'ba_events': [],
            'disconnect_events': [],
            'assoc_events': [],
            'signal_data': {},
            'retransmit_stats': {},
            'tcp_stats': {'packets': 0, 'retransmissions': 0, 'flows': {}},
            'dhcp_events': [],
        }

        report = generate_report(result)

        self.assertIn('## TCP/IP 层重传统计 (Top 10)', report)
        self.assertIn('未解析到明文 IPv4/TCP 数据帧', report)


if __name__ == '__main__':
    unittest.main()
