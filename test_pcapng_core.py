#!/usr/bin/env python3
import os
import struct
import tempfile
import unittest

from pcapng_parser import (
    ADDBA_REQ,
    ADDBA_RESP,
    AUTH,
    CAT_BA,
    DELBA,
    DHCP_ACK,
    DHCP_MSG_NAMES,
    DHCP_NAK,
    PcapngReader,
    parse_capture,
    parse_frame,
)


def _mac_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(':'))


def _management_frame(subtype, body=b'', duration=0):
    header = struct.pack('<HH', subtype << 4, duration)
    header += _mac_bytes('66:77:88:99:aa:bb')
    header += _mac_bytes('00:11:22:33:44:55')
    header += _mac_bytes('66:77:88:99:aa:bb')
    header += struct.pack('<H', 0x0010)
    return header + body


def _pcapng_block(block_type, body):
    block_len = 12 + len(body)
    return (
        struct.pack('<II', block_type, block_len)
        + body
        + struct.pack('<I', block_len)
    )


def _build_capture(link_types, packets):
    capture = _pcapng_block(
        0x0A0D0D0A,
        struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1),
    )
    for link_type in link_types:
        capture += _pcapng_block(1, struct.pack('<HHI', link_type, 0, 65535))
    for index, (interface_id, packet) in enumerate(packets, start=1):
        padding = b'\x00' * ((-len(packet)) % 4)
        timestamp = index * 1_000_000
        epb_body = struct.pack(
            '<IIIII',
            interface_id,
            timestamp >> 32,
            timestamp & 0xFFFFFFFF,
            len(packet),
            len(packet),
        )
        capture += _pcapng_block(6, epb_body + packet + padding)
    return capture


def _parse_temporary_capture(capture):
    with tempfile.NamedTemporaryFile(suffix='.pcapng', delete=False) as tmp:
        tmp.write(capture)
        path = tmp.name
    try:
        return parse_capture(path)
    finally:
        os.unlink(path)


def _addba_parameter(tid, bufsize, amsdu=False, immediate=False):
    return (
        (bufsize << 6)
        | (tid << 2)
        | (int(immediate) << 1)
        | int(amsdu)
    )


class InterfaceDescriptionTest(unittest.TestCase):
    def test_idb_reads_reserved_and_full_snap_len_fields(self):
        reader = PcapngReader.__new__(PcapngReader)
        reader.interfaces = []
        reader._ts_resolutions = []

        reader._parse_idb(struct.pack('<HHI', 127, 0xBEEF, 65535))

        self.assertEqual(
            reader.interfaces,
            [{'link_type': 127, 'snap_len': 65535}],
        )


class BlockAckParameterTest(unittest.TestCase):
    def test_addba_request_uses_little_endian_bit_fields(self):
        parameter = _addba_parameter(
            tid=5,
            bufsize=64,
            amsdu=True,
            immediate=True,
        )
        body = (
            bytes((CAT_BA, ADDBA_REQ, 7))
            + struct.pack('<HHH', parameter, 25, 321 << 4)
        )

        ba = parse_frame(_management_frame(0xD, body))['ba']

        self.assertEqual(ba['action'], 'ADDBA Request')
        self.assertEqual(ba['dialog'], 7)
        self.assertEqual(ba['tid'], 5)
        self.assertEqual(ba['bufsize'], 64)
        self.assertTrue(ba['amsdu'])
        self.assertEqual(ba['policy'], 'Immediate')
        self.assertEqual(ba['timeout'], 25)
        self.assertEqual(ba['seq_start'], 321)

    def test_addba_response_uses_little_endian_bit_fields(self):
        parameter = _addba_parameter(tid=9, bufsize=512)
        body = (
            bytes((CAT_BA, ADDBA_RESP, 3))
            + struct.pack('<HHH', 37, parameter, 50)
        )

        ba = parse_frame(_management_frame(0xD, body))['ba']

        self.assertEqual(ba['action'], 'ADDBA Response')
        self.assertEqual(ba['dialog'], 3)
        self.assertEqual(ba['status'], 37)
        self.assertFalse(ba['status_ok'])
        self.assertEqual(ba['tid'], 9)
        self.assertEqual(ba['bufsize'], 512)
        self.assertEqual(ba['timeout'], 50)

    def test_delba_uses_little_endian_parameter(self):
        parameter = (11 << 12) | (1 << 11)
        body = bytes((CAT_BA, DELBA)) + struct.pack('<HH', parameter, 39)

        ba = parse_frame(_management_frame(0xD, body))['ba']

        self.assertEqual(
            ba,
            {
                'action': 'DELBA',
                'tid': 11,
                'initiator': 'Originator',
                'reason': 39,
            },
        )


class LinkTypeDispatchTest(unittest.TestCase):
    def test_raw_80211_uses_packet_interface_id(self):
        raw_frame = _management_frame(0x0, duration=24)
        capture = _build_capture([127, 105], [(1, raw_frame)])

        result = _parse_temporary_capture(capture)

        self.assertEqual(result['meta']['total_packets'], 1)
        self.assertEqual(result['frame_stats']['Management'], 1)
        self.assertEqual(
            result['assoc_events'][0]['type'],
            'Association Request',
        )
        self.assertEqual(result['assoc_events'][0]['src'], '00:11:22:33:44:55')

    def test_radiotap_uses_packet_interface_id(self):
        auth_body = struct.pack('<HHH', 0, 2, 0)
        raw_frame = _management_frame(AUTH, auth_body)
        radiotap = struct.pack('<BBHI', 0, 0, 8, 0)
        capture = _build_capture([105, 127], [(1, radiotap + raw_frame)])

        result = _parse_temporary_capture(capture)

        self.assertEqual(result['meta']['total_packets'], 1)
        self.assertEqual(result['assoc_events'][0]['type'], 'Authentication')
        self.assertEqual(result['assoc_events'][0]['src'], '00:11:22:33:44:55')
        self.assertEqual(result['assoc_events'][0]['status'], 0)

    def test_unknown_link_type_is_skipped(self):
        raw_frame = _management_frame(0x0)
        capture = _build_capture([105, 1], [(1, raw_frame)])

        result = _parse_temporary_capture(capture)

        self.assertEqual(result['meta']['reader_total'], 1)
        self.assertEqual(result['meta']['total_packets'], 0)
        self.assertEqual(result['frame_stats'], {})

    def test_mac_filter_total_counts_only_selected_frames(self):
        selected = _management_frame(0x0)
        rejected = bytearray(_management_frame(0x0))
        rejected[10:16] = _mac_bytes('00:aa:bb:cc:dd:ee')
        capture = _build_capture(
            [105],
            [(0, selected), (0, bytes(rejected))],
        )

        with tempfile.NamedTemporaryFile(suffix='.pcapng', delete=False) as tmp:
            tmp.write(capture)
            path = tmp.name
        try:
            result = parse_capture(path, mac_filter=['00:11:22:33:44:55'])
        finally:
            os.unlink(path)

        self.assertEqual(result['meta']['reader_total'], 2)
        self.assertEqual(result['meta']['filtered_packets'], 1)
        self.assertEqual(result['meta']['total_packets'], 1)
        self.assertEqual(result['frame_stats']['Management'], 1)

    def test_new_section_resets_interface_ids(self):
        radiotap_frame = (
            struct.pack('<BBHI', 0, 0, 8, 0)
            + _management_frame(AUTH, struct.pack('<HHH', 0, 1, 0))
        )
        raw_frame = _management_frame(0x0)
        capture = (
            _build_capture([127], [(0, radiotap_frame)])
            + _build_capture([105], [(0, raw_frame)])
        )

        result = _parse_temporary_capture(capture)

        self.assertEqual(result['meta']['reader_total'], 2)
        self.assertEqual(result['meta']['total_packets'], 2)
        self.assertEqual(
            [event['type'] for event in result['assoc_events']],
            ['Authentication', 'Association Request'],
        )
        self.assertEqual(result['meta']['interfaces'][0]['link_type'], 105)


class DhcpMessageTypeTest(unittest.TestCase):
    def test_ack_and_nak_values_match_rfc_assignments(self):
        self.assertEqual(DHCP_ACK, 5)
        self.assertEqual(DHCP_NAK, 6)
        self.assertEqual(DHCP_MSG_NAMES[5], 'ACK')
        self.assertEqual(DHCP_MSG_NAMES[6], 'NAK')


if __name__ == '__main__':
    unittest.main()
