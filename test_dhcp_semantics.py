#!/usr/bin/env python3
import struct
import unittest

from analyze import detect_dhcp_issues, generate_report
from pcapng_parser import (
    DHCP_ACK,
    DHCP_NAK,
    _parse_dhcp_from_frame,
    parse_frame,
)


def mac_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(':'))


def build_dhcp_frame(message_type):
    wifi = struct.pack('<HH', 0x0008, 0)
    wifi += mac_bytes('66:77:88:99:aa:bb')
    wifi += mac_bytes('00:11:22:33:44:55')
    wifi += mac_bytes('66:77:88:99:aa:bb')
    wifi += struct.pack('<H', 0x0010)

    dhcp = bytearray(240)
    dhcp[0:3] = b'\x02\x01\x06'
    dhcp[4:8] = struct.pack('>I', 0x12345678)
    dhcp[28:34] = mac_bytes('00:11:22:33:44:55')
    dhcp[236:240] = b'\x63\x82\x53\x63'
    options = bytes((53, 1, message_type, 255))

    udp_len = 8 + len(dhcp) + len(options)
    udp = struct.pack('>HHHH', 67, 68, udp_len, 0) + dhcp + options
    ip_len = 20 + len(udp)
    ip = struct.pack(
        '>BBHHHBBH4s4s',
        0x45,
        0,
        ip_len,
        0,
        0,
        64,
        17,
        0,
        bytes((192, 168, 1, 1)),
        bytes((255, 255, 255, 255)),
    )
    return wifi + b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + ip + udp


def dhcp_event(message_type, message_name, operation, time):
    return {
        'time': time,
        'msg_type': message_type,
        'msg_name': message_name,
        'src_mac': '00:11:22:33:44:55',
        'dst_mac': '66:77:88:99:aa:bb',
        'client_mac': '00:11:22:33:44:55',
        'xid': 0x12345678,
        'op': operation,
    }


class DhcpMessageTypeTest(unittest.TestCase):
    def test_parser_maps_ack_and_nak_to_standard_message_types(self):
        ack_frame = build_dhcp_frame(DHCP_ACK)
        nak_frame = build_dhcp_frame(DHCP_NAK)

        ack = _parse_dhcp_from_frame(parse_frame(ack_frame), ack_frame)
        nak = _parse_dhcp_from_frame(parse_frame(nak_frame), nak_frame)

        self.assertEqual((DHCP_ACK, ack['msg_name']), (5, 'ACK'))
        self.assertEqual((DHCP_NAK, nak['msg_name']), (6, 'NAK'))

    def test_ack_is_reported_as_success_not_rejection(self):
        events = [
            dhcp_event(1, 'Discover', 'Request', 0.0),
            dhcp_event(2, 'Offer', 'Reply', 0.1),
            dhcp_event(3, 'Request', 'Request', 0.2),
            dhcp_event(DHCP_ACK, 'ACK', 'Reply', 0.3),
        ]

        categories = {issue['category'] for issue in detect_dhcp_issues(events)}
        self.assertNotIn('DHCP NAK', categories)
        self.assertNotIn('DHCP Request 被 NAK', categories)
        self.assertIn('结果: ACK(成功)', generate_report(self._result(events)))

    def test_nak_is_reported_as_rejection(self):
        events = [
            dhcp_event(3, 'Request', 'Request', 0.0),
            dhcp_event(DHCP_NAK, 'NAK', 'Reply', 0.1),
        ]

        categories = {issue['category'] for issue in detect_dhcp_issues(events)}
        self.assertIn('DHCP NAK', categories)
        self.assertIn('DHCP Request 被 NAK', categories)
        self.assertIn('结果: NAK(失败)', generate_report(self._result(events)))

    @staticmethod
    def _result(events):
        return {
            'meta': {
                'filepath': 'sample.pcapng',
                'file_size_mb': 0.1,
                'reader_total': 1,
                'total_packets': 1,
                'duration': 1.0,
                'interfaces': [],
            },
            'frame_stats': {'Data': 1},
            'ba_events': [],
            'disconnect_events': [],
            'assoc_events': [],
            'dhcp_events': events,
            'signal_data': {},
            'retransmit_stats': {},
            'tcp_stats': {'packets': 0, 'retransmissions': 0, 'flows': {}},
        }


if __name__ == '__main__':
    unittest.main()
