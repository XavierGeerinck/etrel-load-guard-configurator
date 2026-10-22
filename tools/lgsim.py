#!/usr/bin/env python3
"""lgsim - a simulated Etrel Load Guard for testing lgconf without hardware.

Implements the device side of docs/PROTOCOL.md as seen from the official configurator.
Behaviour the configurator does not reveal (validation rules, which commands are
ACKed) is a guess; the reply layouts match what the configurator parses.

    python3 tools/lgsim.py                 # listen on UDP 10102
    python3 tools/lgsim.py --port 11102    # then: lgconf.py --device-port 11102 ...
"""

import argparse
import math
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import lgconf as lg  # noqa: E402


class SimulatedLoadGuard:
    def __init__(self, host="0.0.0.0", port=lg.DEVICE_PORT, serial=1700123,
                 mac=b"\x00\x1e\xc0\x12\x34\x56", ip="192.168.1.50", verbose=False):
        self.serial = serial
        self.mac = mac  # display order
        self.verbose = verbose
        self.counter = 0
        self.clock_offset_ms = 0
        self.boot_ms = lg.now_ms()
        self.dhcp = False
        self.ip = ip
        self.netmask = "255.255.255.0"
        self.gateway = "192.168.1.1"
        self.servers = [lg.ServerSettings(True, "192.168.1.60", lg.CHARGER_PORT, 1600001),
                        lg.ServerSettings(False, "0.0.0.0", 0, 0)]
        self.measurement_type = 1
        self.interval = 350
        self.received = []  # (type, payload) of every packet handled, for tests
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()

    # -- helpers ------------------------------------------------------------------

    def device_time(self):
        return lg.now_ms() + self.clock_offset_ms

    def packet(self, msg_type, payload=b""):
        self.counter = (self.counter + 1) & 0xFFFF
        return lg.encode_packet(msg_type, self.counter, payload, self.device_time())

    def nack(self, req, code):
        return self.packet(lg.NACK, struct.pack("<qhh", req.timestamp, req.counter, code))

    def system_about(self):
        return struct.pack("<qqHHH", lg.now_ms() - self.boot_ms, self.serial, 3, 0, 142) \
            + self.mac[::-1] + struct.pack("<q", 0)

    def measurement(self):
        t = time.time()
        wobble = math.sin(t / 7)
        volts = [int((230 + 2 * wobble + i) * 100) for i in range(3)]
        amps = [int((8 + 3 * math.sin(t / 5 + i)) * 1000) for i in range(3)]
        amps.append(sum(amps))
        watts = [int(v / 100 * a / 1000 * 0.97) for v, a in zip(volts, amps[:3])]
        watts.append(sum(watts))
        vars_ = [w // 8 for w in watts]
        va = [int(v / 100 * a / 1000) for v, a in zip(volts, amps[:3])]
        va.append(sum(va))
        pf = [int(1000 * w / s) if s else 0 for w, s in zip(watts, va)]
        uptime = lg.now_ms() - self.boot_ms
        energy = [int((1234.5 + i + uptime / 3.6e6) * 1e6) for i in range(3)]
        energy.append(sum(energy))
        i32 = amps + watts + vars_ + va + [0]
        i16 = pf + [5000, 31]
        i64 = energy + [0] * 4 + [e // 9 for e in energy] + [0] * 4 + [0] * 21
        return lg.MEASUREMENT_FORMAT.pack(uptime, self.device_time(), *volts, *i32, *i16, *i64,
                                          *([0] * 16))

    def server_status(self):
        out = b""
        for s in self.servers:
            ok = 1 if s.enabled else 0
            out += s.encode() + struct.pack("<qqB", self.device_time() if ok else 0, 0, ok)
        return out

    # -- protocol -----------------------------------------------------------------

    def handle(self, data):
        req = lg.decode_packet(data)
        if req is None:
            return []
        self.received.append((req.type, req.payload))
        t, p = req.type, req.payload
        if t == lg.GET_SERIAL:
            return [self.packet(t, struct.pack("<Q", self.serial))]
        if t == lg.GET_SYSTEM_ABOUT:
            return [self.packet(t, self.system_about())]
        if t == lg.GET_HW_VERSION:
            return [self.packet(t, struct.pack("<h", 3))]
        if t == lg.GET_MAC:
            return [self.packet(t, self.mac[::-1])]
        if t == lg.GET_IP_SETTINGS:
            return [self.packet(t, struct.pack("<BIII", self.dhcp, lg.ipv4_int(self.ip),
                                               lg.ipv4_int(self.netmask),
                                               lg.ipv4_int(self.gateway)))]
        if t == lg.GET_MEASUREMENT_TYPE:
            return [self.packet(t, bytes([self.measurement_type]))]
        if t == lg.GET_MEASUREMENT_INTERVAL:
            return [self.packet(t, struct.pack("<H", self.interval))]
        if t == lg.GET_SERVER_SETTINGS:
            return [self.packet(t, self.server_status())]
        if t == lg.MEASUREMENTS_ALL:
            return [self.packet(t, self.measurement())]
        if t in (lg.ACK_MEASUREMENTS, lg.ACK_CURRENTS, lg.ACK_ENERGY_BUFFER):
            return []
        if t == lg.SYNC_TIME:
            self.clock_offset_ms = req.timestamp - lg.now_ms()
            return [self.packet(lg.ACK)]
        if t == lg.SET_IP_SETTINGS:
            if len(p) < 13:
                return [self.nack(req, 1)]
            if p[0] == 1:
                self.dhcp = True
            else:
                _, ip, mask, gw = struct.unpack_from("<BIII", p)
                if ip == 0 or gw == 0:
                    return [self.nack(req, 6)]
                to_str = lambda v: str(lg.ipaddress.IPv4Address(v))  # noqa: E731
                self.dhcp, self.ip, self.netmask, self.gateway = False, to_str(ip), to_str(mask), \
                    to_str(gw)
            return [self.packet(lg.ACK)]
        if t == lg.SET_MEASUREMENT_TYPE:
            if not p or p[0] > 2:
                return [self.nack(req, 8)]
            self.measurement_type = p[0]
            return [self.packet(lg.ACK)]
        if t == lg.SET_MEASUREMENT_INTERVAL:
            value = struct.unpack_from("<h", p)[0]
            if value < lg.INTERVAL_MIN:
                return [self.nack(req, 23)]
            if value > lg.INTERVAL_MAX:
                return [self.nack(req, 24)]
            self.interval = value
            return [self.packet(lg.ACK)]
        if t == lg.SET_SERVER_SETTINGS:
            if len(p) < 30:
                return [self.nack(req, 1)]
            a, b = lg.ServerSettings.decode(p[:15]), lg.ServerSettings.decode(p[15:30])
            if a.enabled and b.enabled and (a.ip, a.serial) == (b.ip, b.serial):
                return [self.nack(req, 7)]
            self.servers = [a, b]
            return [self.packet(lg.ACK)]
        return [self.nack(req, 13)]

    def serve_forever(self):
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            for reply in self.handle(data):
                if self.verbose:
                    print(f"{addr[0]}:{addr[1]} 0x{data[10]:02X} -> 0x{reply[10]:02X}")
                self.sock.sendto(reply, addr)

    def start(self):
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        return thread

    def stop(self):
        self._stop.set()
        self.sock.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=lg.DEVICE_PORT)
    ap.add_argument("--serial", type=int, default=1700123)
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()
    sim = SimulatedLoadGuard(args.host, args.port, args.serial, verbose=not args.quiet)
    print(f"Simulated Load Guard SN {sim.serial} listening on UDP {args.host}:{sim.port}")
    try:
        sim.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
