"""End-to-end: lgconf client against the simulated device over real UDP sockets on localhost."""

import contextlib
import io
import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import lgconf as lg  # noqa: E402
from lgsim import SimulatedLoadGuard  # noqa: E402

HOST = "127.0.0.1"


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        self.sim = SimulatedLoadGuard(HOST, 0)
        self.sim.start()
        self.client = lg.LoadGuardClient(HOST, 0, self.sim.port)

    def tearDown(self):
        self.client.close()
        self.sim.stop()

    def cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = lg.main(["--bind", HOST, "--local-port", "0",
                            "--device-port", str(self.sim.port), *argv])
        return code, out.getvalue()

    def test_discover(self):
        devices = self.client.discover(timeout=0.5, targets=[HOST], repeats=2)
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].serial, self.sim.serial)
        self.assertEqual(devices[0].about.mac, "00:1e:c0:12:34:56")
        self.assertEqual(devices[0].about.sw_version, 142)

    def test_reads(self):
        self.assertEqual(self.client.serial(HOST), self.sim.serial)
        net = self.client.ip_settings(HOST)
        self.assertEqual((net.ip, net.netmask, net.gateway),
                         ("192.168.1.50", "255.255.255.0", "192.168.1.1"))
        master, secondary = self.client.server_status(HOST)
        self.assertTrue(master.ok)
        self.assertFalse(secondary.settings.enabled)
        self.assertEqual(self.client.measurement_type(HOST), 1)
        self.assertEqual(self.client.measurement_interval(HOST), 350)

    def test_measurement_is_acknowledged(self):
        m = self.client.measurements(HOST)
        self.assertAlmostEqual(m.frequency, 50.0)
        self.assertTrue(225 < m.voltage[0] < 240)
        self.client.receive(0.2)  # let the simulator process the ACK
        self.assertIn(lg.ACK_MEASUREMENTS, [t for t, _ in self.sim.received])

    def test_set_network_static(self):
        code, _ = self.cli("set-network", HOST, "--static", "--address", "10.1.2.3",
                           "--netmask", "255.255.0.0", "--gateway", "10.1.0.1", "--yes")
        self.assertEqual(code, 0)
        self.assertEqual(self.sim.ip, "10.1.2.3")
        self.assertEqual(self.sim.netmask, "255.255.0.0")
        self.assertEqual(self.client.ip_settings(HOST).netmask, "255.255.0.0")

    def test_set_chargers_with_redundancy(self):
        code, _ = self.cli("set-chargers", HOST, "--master-ip", "192.168.1.61",
                           "--master-serial", "111", "--secondary-ip", "192.168.1.62",
                           "--secondary-serial", "222", "--yes")
        self.assertEqual(code, 0)
        self.assertEqual([(s.ip, s.port, s.serial) for s in self.sim.servers],
                         [("192.168.1.61", 10105, 111), ("192.168.1.62", 10105, 222)])

    def test_nack_is_reported(self):
        with self.assertRaisesRegex(lg.LoadGuardError, "too low"):
            self.client.command(HOST, lg.SET_MEASUREMENT_INTERVAL, b"\x32\x00")  # 50 ms

    def test_set_reporting_and_info(self):
        code, _ = self.cli("set-reporting", HOST, "--type", "currents", "--interval", "1000",
                           "--yes")
        self.assertEqual(code, 0)
        code, out = self.cli("info", HOST)
        self.assertEqual(code, 0)
        self.assertIn("currents", out)
        self.assertIn("1000 ms", out)

    def test_sync_time(self):
        code, _ = self.cli("sync-time", HOST, "--yes")
        self.assertEqual(code, 0)
        self.assertLess(abs(self.sim.clock_offset_ms), 2000)

    def test_dry_run_sends_nothing(self):
        code, out = self.cli("set-network", HOST, "--dhcp", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("01 00 00 00 00 00 00 00 00 00 00 00 00", out)
        self.assertNotIn(lg.SET_IP_SETTINGS, [t for t, _ in self.sim.received])

    def test_measure_cli(self):
        code, out = self.cli("measure", HOST)
        self.assertEqual(code, 0)
        self.assertIn("Voltage [V]", out)
        self.assertIn("Frequency 50.00 Hz", out)


if __name__ == "__main__":
    unittest.main()
