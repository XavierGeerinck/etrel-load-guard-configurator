"""Byte-level checks of the encoder/decoder.

Expected bytes are written out by hand from docs/PROTOCOL.md (not produced by lgconf),
and the decoders are checked against payloads captured from a real Load Guard
(tests/fixtures/real_device.json, identifiers anonymised).
"""

import json
import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import lgconf as lg  # noqa: E402

with open(os.path.join(HERE, "fixtures", "real_device.json")) as f:
    REAL = {int(k, 16): bytes.fromhex(v) for k, v in json.load(f)["payloads"].items()}


class HeaderTest(unittest.TestCase):
    def test_header_is_little_endian_ts_counter_type(self):
        pkt = lg.encode_packet(0xA2, 0x0A0B, b"", timestamp_ms=0x0102030405060708)
        self.assertEqual(pkt.hex(), "0807060504030201" "0b0a" "a2")

    def test_counter_wraps_into_int16(self):
        pkt = lg.encode_packet(0x7F, 0xFFFF, b"", timestamp_ms=0)
        self.assertEqual(pkt[8:10], b"\xff\xff")

    def test_decode_real_discovery_reply(self):
        # A 0x7F reply as a real device sent it (serial anonymised).
        p = lg.decode_packet(bytes.fromhex("4aa4d464a1010000" "0247" "7f" "4e61bc0000000000"))
        self.assertEqual((p.timestamp, p.counter, p.type), (1792693019722, 0x4702, 0x7F))
        self.assertEqual(struct.unpack("<Q", p.payload)[0], 12345678)

    def test_short_datagram_ignored(self):
        self.assertIsNone(lg.decode_packet(b"\x00" * 10))


class IpSettingsTest(unittest.TestCase):
    def test_static(self):
        payload = lg.encode_ip_settings(False, "192.168.1.10", 24, "192.168.1.1")
        # Netmask bytes 00 FF FF FF are what the official tool builds for /24 (0x40a690).
        self.assertEqual(payload.hex(), "00" "0a01a8c0" "00ffffff" "0101a8c0")

    def test_odd_prefixes(self):
        self.assertEqual(lg.encode_ip_settings(False, "10.0.0.2", 20, "10.0.0.1")[5:9].hex(),
                         "00f0ffff")
        self.assertEqual(lg.encode_ip_settings(False, "10.0.0.2", 0, "10.0.0.1")[5:9].hex(),
                         "00000000")
        self.assertEqual(lg.encode_ip_settings(False, "10.0.0.2", 32, "10.0.0.1")[5:9].hex(),
                         "ffffffff")

    def test_dhcp_is_one_and_twelve_zeros(self):
        self.assertEqual(lg.encode_ip_settings(True), b"\x01" + bytes(12))

    def test_prefix_from_netmask_counts_bits_like_gui(self):
        self.assertEqual(lg.prefix_from_netmask("255.255.255.0"), 24)
        self.assertEqual(lg.prefix_from_netmask("/16"), 16)
        self.assertEqual(lg.prefix_from_netmask("255.255.240.0"), 20)

    def test_decode_real(self):
        net = lg.IpSettings.decode(REAL[lg.GET_IP_SETTINGS])
        self.assertEqual(net, lg.IpSettings(False, "192.168.1.249", "255.255.255.0",
                                            "192.168.1.1"))

    def test_roundtrip_matches_real_reply_format(self):
        sent = lg.encode_ip_settings(False, "192.168.1.249", 24, "192.168.1.1")
        self.assertEqual(sent, REAL[lg.GET_IP_SETTINGS])


class ServerSettingsTest(unittest.TestCase):
    def test_master_and_disabled_secondary(self):
        master = lg.ServerSettings(True, "10.0.0.2", 10105, 1600001)
        off = lg.ServerSettings(False, "1.2.3.4", 10105, 5)
        payload = lg.encode_server_settings(master, off)
        self.assertEqual(len(payload), 30)
        self.assertEqual(payload[:15].hex(), "01" "0200000a" "7927" "016a180000000000")
        self.assertEqual(payload[15:], bytes(15))

    def test_decode_real(self):
        master, secondary = lg.decode_server_status(REAL[lg.GET_SERVER_SETTINGS])
        self.assertEqual(master.settings, lg.ServerSettings(True, "192.168.1.232", 10105,
                                                            87654321))
        self.assertTrue(master.ok)
        self.assertGreater(master.last_ack_ms, master.last_fail_ms)
        self.assertFalse(secondary.settings.enabled)
        self.assertFalse(secondary.ok)


class SystemAboutTest(unittest.TestCase):
    def test_layout_and_mac_order(self):
        p = (struct.pack("<qq", 90061000, 1700123) + struct.pack("<HHH", 3, 9, 142)
             + bytes.fromhex("010203040506") + struct.pack("<q", 77))
        a = lg.SystemAbout.decode(p)
        self.assertEqual(a.serial, 1700123)
        self.assertEqual((a.hw_version, a.unknown_u16, a.sw_version), (3, 9, 142))
        self.assertEqual(a.mac, "06:05:04:03:02:01")
        self.assertEqual(lg.fmt_uptime(a.uptime_ms), "1:01:01:01")

    def test_decode_real(self):
        a = lg.SystemAbout.decode(REAL[lg.GET_SYSTEM_ABOUT])
        self.assertEqual((a.serial, a.sw_version, a.hw_version), (12345678, 10, 257))
        self.assertEqual(a.mac, "02:00:00:00:00:01")
        self.assertEqual(struct.unpack("<Q", REAL[lg.GET_SERIAL])[0], a.serial)


class MeasurementTest(unittest.TestCase):
    def build(self):
        out = struct.pack("<qq", 123456, 1700000000000)
        out += struct.pack("<HHH", 23012, 23100, 22999)                 # 0.01 V
        out += struct.pack("<4i", 8123, 7000, -500, 14623)              # mA
        out += struct.pack("<4i", 1800, 1600, -100, 3300)               # W
        out += struct.pack("<4i", 200, 100, 0, 300)                     # var
        out += struct.pack("<5i", 1870, 1617, 115, 3602, 5)             # VA, unknown
        out += struct.pack("<6h", 962, 989, -869, 916, 4998, -5)        # PF, Hz*100, degC
        out += struct.pack("<4q", 1_000_000, 2_500_000, 0, 3_500_000)   # Wh*1000
        out += struct.pack("<4q", 0, 0, 750_000, 750_000)
        out += struct.pack("<4q", 1, 2, 3, 6)
        out += struct.pack("<4q", 0, 0, 0, 0)
        out += struct.pack("<4q", 4_000_000, 0, 0, 4_000_000)          # VAh*1000
        out += struct.pack("<17q", *range(17))
        out += struct.pack("<16h", *range(16))
        return out

    def test_size_matches_receive_check(self):
        self.assertEqual(lg.MEASUREMENT_FORMAT.size, 430)
        self.assertEqual(len(self.build()), 430)

    def test_fields_and_scales(self):
        m = lg.Measurement.decode(self.build())
        self.assertEqual(m.uptime_ms, 123456)
        self.assertEqual(m.device_time_ms, 1700000000000)
        self.assertEqual(m.voltage, [230.12, 231.0, 229.99])
        self.assertEqual(m.current, [8.123, 7.0, -0.5, 14.623])
        self.assertEqual(m.active_power, [1.8, 1.6, -0.1, 3.3])
        self.assertEqual(m.reactive_power, [0.2, 0.1, 0.0, 0.3])
        self.assertEqual(m.apparent_power, [1.87, 1.617, 0.115, 3.602])
        self.assertEqual(m.power_factor, [0.962, 0.989, -0.869, 0.916])
        self.assertEqual(m.frequency, 49.98)
        self.assertEqual(m.temperature, -5)
        self.assertEqual(m.active_energy_consumed, [1.0, 2.5, 0.0, 3.5])
        self.assertEqual(m.active_energy_produced, [0.0, 0.0, 0.75, 0.75])
        self.assertEqual(m.reactive_energy_consumed, [1e-6, 2e-6, 3e-6, 6e-6])
        self.assertEqual(m.apparent_energy, [4.0, 0.0, 0.0, 4.0])
        self.assertEqual(m.unknown["i32"], [5])
        self.assertEqual(m.unknown["i64"], list(range(17)))
        self.assertEqual(m.unknown["i16_tail"], list(range(16)))

    def test_decode_real_is_physically_consistent(self):
        m = lg.Measurement.decode(REAL[lg.MEASUREMENTS_ALL])
        for v in m.voltage:
            self.assertTrue(200 < v < 260, v)
        self.assertTrue(49.5 < m.frequency < 50.5)
        self.assertTrue(-20 < m.temperature < 80)
        for i in range(3):  # S = V * I, PF = P / S
            self.assertAlmostEqual(m.apparent_power[i], m.voltage[i] * m.current[i] / 1000,
                                   delta=0.01)
            self.assertAlmostEqual(m.power_factor[i], m.active_power[i] / m.apparent_power[i],
                                   delta=0.01)
        self.assertAlmostEqual(sum(m.apparent_power[:3]), m.apparent_power[3], delta=0.003)
        self.assertAlmostEqual(sum(m.apparent_energy[:3]), m.apparent_energy[3], delta=0.01)


class NackTest(unittest.TestCase):
    def test_error_text_from_table(self):
        self.assertEqual(lg.decode_nack(struct.pack("<qhh", 1, 2, 23)),
                         (23, "Measurement sending interval is too low"))
        self.assertEqual(lg.decode_nack(struct.pack("<qhh", 1, 2, 99))[1], "error code 99")
        self.assertEqual(len(lg.NACK_ERRORS), 25)


class SmallRepliesTest(unittest.TestCase):
    def test_real_type_and_interval(self):
        self.assertEqual(REAL[lg.GET_MEASUREMENT_TYPE][0], 1)  # "all"
        self.assertEqual(struct.unpack("<H", REAL[lg.GET_MEASUREMENT_INTERVAL])[0], 750)


if __name__ == "__main__":
    unittest.main()
