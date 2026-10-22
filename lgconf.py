#!/usr/bin/env python3
"""lgconf - open-source console configurator for Etrel Load Guard devices.

Speaks the UDP protocol of the official "Load Guard Configurator" v1.4 (see
docs/PROTOCOL.md). Pure Python 3 standard library; runs on macOS, Linux and Windows.

    python3 lgconf.py discover
    python3 lgconf.py info 192.168.1.50
    python3 lgconf.py measure 192.168.1.50 --watch
"""

import argparse
import ipaddress
import json
import re
import socket
import struct
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime

__version__ = "0.1.0"

DEVICE_PORT = 10102
LOCAL_PORT = 10105
CHARGER_PORT = 10105  # the official GUI always configures chargers with this port

# Everything is little-endian: QDataStream::setByteOrder(1) == QDataStream::LittleEndian.
HEADER = struct.Struct("<qhb")  # int64 timestamp ms, int16 counter, int8 type

# Message types (names follow the slots/signals of the original lg::LoadGuard class).
ACK = 0x01
NACK = 0x02
BOOT = 0x03
BOOT_ACK = 0x04
MEASUREMENTS_ALL = 0x11
MEASUREMENTS_CURRENTS = 0x12
ACK_CURRENTS = 0x13
ACK_MEASUREMENTS = 0x14
ENERGY_BUFFER = 0x19
ACK_ENERGY_BUFFER = 0x1A
GET_IP_SETTINGS = 0x22
GET_MEASUREMENT_TYPE = 0x23
GET_SERVER_SETTINGS = 0x24
GET_MEASUREMENT_INTERVAL = 0x25
HARDWARE_ALL = 0x70
GET_HW_VERSION = 0x7C
GET_MAC = 0x7D
GET_SYSTEM_ABOUT = 0x7E
GET_SERIAL = 0x7F
SYNC_TIME = 0xA1
SET_IP_SETTINGS = 0xA2
SET_MEASUREMENT_TYPE = 0xA3
SET_SERVER_SETTINGS = 0xA4
SET_MEASUREMENT_INTERVAL = 0xA5

MEASUREMENT_TYPES = {"none": 0, "all": 1, "currents": 2}
MEASUREMENT_TYPE_NAMES = {v: k for k, v in MEASUREMENT_TYPES.items()}
INTERVAL_MIN, INTERVAL_MAX = 100, 5000

NACK_ERRORS = [
    "Received error unknown",
    "Received packet too short",
    "MAC address already set",
    "MAC address is not valid",
    "Serial number is already set",
    "Serial number is not valid",
    "IP settings are not valid",
    "Settings for both servers are same",
    "Measurement type is not valid",
    "Reading of register is not allowed",
    "Writing of register is not allowed",
    "Register is not 32bit or reading of register is not allowed",
    "Errors on SPI communication with AFE",
    "UDP message type not valid",
    "AFE is not calibrated yet",
    "Server already enabled",
    "Server list is full",
    "Server is not on list",
    "Hardware version is already set",
    "Hardware version is not valid",
    "Calibration was already started",
    "Calibration was already ended",
    "Server UDP port is not valid",
    "Measurement sending interval is too low",
    "Measurement sending interval is too high",
]


class LoadGuardError(Exception):
    pass


# --------------------------------------------------------------------------- encoding


def now_ms():
    return int(time.time() * 1000)


def to_s8(v):
    return v - 256 if v > 127 else v


def to_s16(v):
    v &= 0xFFFF
    return v - 0x10000 if v > 0x7FFF else v


def encode_packet(msg_type, counter, payload=b"", timestamp_ms=None):
    ts = now_ms() if timestamp_ms is None else timestamp_ms
    return HEADER.pack(ts, to_s16(counter), to_s8(msg_type)) + payload


def ipv4_int(addr):
    return int(ipaddress.IPv4Address(addr))


def prefix_from_netmask(text):
    """Netmask string or /prefix -> prefix length, counting bits per octet like the GUI."""
    text = str(text).strip()
    if text.startswith("/"):
        prefix = int(text[1:])
    elif re.fullmatch(r"\d{1,2}", text):
        prefix = int(text)
    else:
        octets = [int(o) for o in text.split(".")]
        if len(octets) != 4 or any(not 0 <= o <= 255 for o in octets):
            raise ValueError(f"invalid netmask: {text}")
        prefix = sum(bin(o).count("1") for o in octets)
    if not 0 <= prefix <= 32:
        raise ValueError(f"invalid prefix length: {prefix}")
    return prefix


def prefix_to_netmask(prefix):
    return str(ipaddress.IPv4Address((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0))


def encode_ip_settings(dhcp, ip=None, prefix=0, gateway=None):
    """0xA2 payload. IP, netmask and gateway are little-endian u32 like every other field;
    the official tool builds the netmask from a prefix length (0x40a690)."""
    if dhcp:
        return b"\x01" + bytes(12)
    return struct.pack("<BIII", 0, ipv4_int(ip), ipv4_int(prefix_to_netmask(prefix)),
                       ipv4_int(gateway))


@dataclass
class ServerSettings:
    enabled: bool
    ip: str
    port: int
    serial: int

    SIZE = 15

    def encode(self):
        if not self.enabled:
            return bytes(self.SIZE)
        return struct.pack("<BIHQ", 1, ipv4_int(self.ip), self.port, self.serial)

    @classmethod
    def decode(cls, data):
        enabled, ip, port, serial = struct.unpack("<BIHQ", data[:cls.SIZE])
        return cls(enabled == 1, str(ipaddress.IPv4Address(ip)), port, serial)


def encode_server_settings(master, secondary):
    return master.encode() + secondary.encode()


# --------------------------------------------------------------------------- decoding


@dataclass
class Packet:
    timestamp: int
    counter: int
    type: int
    payload: bytes
    src: tuple = ("", 0)


def decode_packet(data, src=("", 0)):
    if len(data) < HEADER.size:
        return None
    ts, counter, mtype = HEADER.unpack_from(data)
    return Packet(ts, counter, mtype & 0xFF, bytes(data[HEADER.size:]), src)


def format_mac(wire6):
    """The MAC is a little-endian 48-bit value on the wire; print it in the usual order."""
    return ":".join(f"{b:02x}" for b in reversed(wire6))


@dataclass
class SystemAbout:
    uptime_ms: int
    serial: int
    hw_version: int
    unknown_u16: int
    sw_version: int
    mac: str
    unknown_i64: int = 0

    @classmethod
    def decode(cls, p):
        uptime, serial, hw, unk, sw = struct.unpack_from("<qqHHH", p)
        mac = format_mac(p[22:28])
        extra = struct.unpack_from("<q", p, 28)[0] if len(p) >= 36 else 0
        return cls(uptime, serial, hw, unk, sw, mac, extra)


@dataclass
class IpSettings:
    dhcp: bool
    ip: str
    netmask: str
    gateway: str

    @classmethod
    def decode(cls, p):
        dhcp, ip, mask, gw = struct.unpack_from("<BIII", p)
        return cls(dhcp == 1, *(str(ipaddress.IPv4Address(v)) for v in (ip, mask, gw)))


@dataclass
class ServerStatus:
    settings: ServerSettings
    last_ack_ms: int
    last_fail_ms: int
    ok: bool

    SIZE = 32

    @classmethod
    def decode(cls, data):
        s = ServerSettings.decode(data)
        ack, fail, ok = struct.unpack_from("<qqB", data, ServerSettings.SIZE)
        return cls(s, ack, fail, ok == 1)


def decode_server_status(p):
    return ServerStatus.decode(p[0:32]), ServerStatus.decode(p[32:64])


MEASUREMENT_FORMAT = struct.Struct("<qq3H17i6h37q16h")  # 430 bytes


@dataclass
class Measurement:
    """MEASUREMENT_ALL. Lists are [L1, L2, L3, total]; voltage is [L1, L2, L3].

    apparent_power, power_factor and apparent_energy are not shown by the official GUI;
    their meaning is inferred from real readings (S = V*I, PF = P/S, L1+L2+L3 = total).
    """
    uptime_ms: int
    device_time_ms: int
    voltage: list                   # V
    current: list                   # A ("total" as labelled by the GUI; not the sum)
    active_power: list              # kW
    reactive_power: list            # kVAr
    apparent_power: list            # kVA (inferred)
    power_factor: list              # (inferred)
    frequency: float                # Hz
    temperature: int                # degC
    active_energy_consumed: list    # kWh
    active_energy_produced: list    # kWh
    reactive_energy_consumed: list  # kVArh
    reactive_energy_produced: list  # kVArh
    apparent_energy: list           # kVAh (inferred)
    unknown: dict = field(default_factory=dict)

    @classmethod
    def decode(cls, p):
        v = MEASUREMENT_FORMAT.unpack_from(p)
        i32 = v[5:22]
        i16 = v[22:28]
        i64 = v[28:65]
        return cls(
            uptime_ms=v[0],
            device_time_ms=v[1],
            voltage=[x / 100 for x in v[2:5]],
            current=[x / 1000 for x in i32[0:4]],
            active_power=[x / 1000 for x in i32[4:8]],
            reactive_power=[x / 1000 for x in i32[8:12]],
            apparent_power=[x / 1000 for x in i32[12:16]],
            power_factor=[x / 1000 for x in i16[0:4]],
            frequency=i16[4] / 100,
            temperature=i16[5],
            active_energy_consumed=[x / 1e6 for x in i64[0:4]],
            active_energy_produced=[x / 1e6 for x in i64[4:8]],
            reactive_energy_consumed=[x / 1e6 for x in i64[8:12]],
            reactive_energy_produced=[x / 1e6 for x in i64[12:16]],
            apparent_energy=[x / 1e6 for x in i64[16:20]],
            unknown={"i32": [i32[16]], "i64": list(i64[20:37]), "i16_tail": list(v[65:81])},
        )


def decode_nack(p):
    ts, counter, code = struct.unpack_from("<qhh", p)
    text = NACK_ERRORS[code] if 0 <= code < len(NACK_ERRORS) else f"error code {code}"
    return code, text


# --------------------------------------------------------------------------- network


def local_networks():
    """IPv4 networks of the up interfaces (excluding loopback), from ifconfig or ip."""
    nets = []
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3).stdout
        for addr, mask in re.findall(r"inet ([\d.]+) netmask (0x[0-9a-f]+|[\d.]+)", out):
            mask = str(ipaddress.IPv4Address(int(mask, 16))) if mask.startswith("0x") else mask
            nets.append(ipaddress.IPv4Interface(f"{addr}/{mask}").network)
        nets += [ipaddress.IPv4Interface(f"{a}/{m}").network
                 for a, m in re.findall(r"inet addr:([\d.]+).*?Mask:([\d.]+)", out)]
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    if not nets:
        try:
            out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True,
                                 timeout=3).stdout
            nets += [ipaddress.IPv4Interface(n).network
                     for n in re.findall(r"inet ([\d.]+/\d+)", out)]
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    return [n for n in dict.fromkeys(nets) if not n.is_loopback and n.prefixlen < 32]


def broadcast_addresses():
    """Limited broadcast plus the directed broadcast of every local network."""
    return ["255.255.255.255"] + [str(n.broadcast_address) for n in local_networks()]


@dataclass
class Device:
    ip: str
    serial: int
    about: SystemAbout = None


class LoadGuardClient:
    def __init__(self, bind="0.0.0.0", local_port=LOCAL_PORT, device_port=DEVICE_PORT,
                 verbose=False):
        self.bind_addr = (bind, local_port)
        self.device_port = device_port
        self.verbose = verbose
        self.counter = 0
        self._broadcasts = None
        self._lan = None
        self._contacted = set()  # IPs this socket has received from (see send_to_device)
        self.sock = None
        self._open()

    def _open(self):
        if self.sock is not None:
            self.sock.close()
        self._contacted.clear()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            self.sock.bind(self.bind_addr)
        except OSError as e:
            raise LoadGuardError(
                f"cannot bind UDP {self.bind_addr[0]}:{self.bind_addr[1]} ({e}). Is the official "
                "configurator or another lgconf running? Use --local-port to pick another "
                "port.") from e

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _log(self, direction, data, addr):
        if self.verbose:
            print(f"{direction} {addr[0]}:{addr[1]} {data.hex(' ')}", file=sys.stderr)

    def send(self, ip, msg_type, payload=b""):
        self.counter = (self.counter + 1) & 0xFFFF
        data = encode_packet(msg_type, self.counter, payload)
        self._log(">>", data, (ip, self.device_port))
        try:
            self.sock.sendto(data, (ip, self.device_port))
        except OSError as e:
            if self.verbose:
                print(f"   send to {ip} failed: {e}", file=sys.stderr)
            return False
        return True

    def broadcast(self, msg_type, targets=None):
        if targets is None:
            if self._broadcasts is None:
                self._broadcasts = broadcast_addresses()
            targets = self._broadcasts
        for t in targets:
            self.send(t, msg_type)

    def _on_lan(self, ip):
        if self._lan is None:
            self._lan = local_networks()
        return any(ipaddress.IPv4Address(ip) in n for n in self._lan)

    def _wait_for(self, ip, timeout):
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            pkt = self.receive(left)
            if pkt is not None and pkt.src[0] == ip:
                return True
        return False

    def send_to_device(self, ip, msg_type, payload=b""):
        """Unicast to a device, working around macOS refusing it with EHOSTUNREACH.

        Without the Local Network permission for the terminal app, macOS refuses unicast to
        a LAN host on a socket that has not yet received from that host, and a socket that
        got refused also stops receiving. So before the first unicast we broadcast a
        discovery probe and wait for the device's answer; if unicast is still refused we
        start over on a fresh socket.
        """
        if sys.platform != "darwin" or not self._on_lan(ip):
            return self.send(ip, msg_type, payload)
        for attempt in range(2):
            if ip not in self._contacted:
                self._contacted.add(ip)
                self.broadcast(GET_SERIAL)
                self._wait_for(ip, 1.5)
            if self.send(ip, msg_type, payload):
                return True
            if attempt == 0:
                self._open()
        return False

    def _auto_ack(self, pkt):
        """Acknowledge pushed data exactly like the official configurator does."""
        ip = pkt.src[0]
        if pkt.type == MEASUREMENTS_ALL:
            self.send(ip, ACK_MEASUREMENTS, struct.pack("<qh", pkt.timestamp, pkt.counter))
        elif pkt.type == MEASUREMENTS_CURRENTS:
            self.send(ip, ACK_CURRENTS, struct.pack("<qh", pkt.timestamp, pkt.counter))
        elif pkt.type == ENERGY_BUFFER and len(pkt.payload) >= 9:
            count = pkt.payload[0]
            ts = struct.unpack_from("<q", pkt.payload, 1)[0]
            self.send(ip, ACK_ENERGY_BUFFER, struct.pack("<Bq", count, ts))

    def receive(self, timeout):
        """Next packet within `timeout` seconds, or None."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.sock.settimeout(remaining)
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                return None
            except ConnectionResetError:  # Windows reports ICMP port unreachable this way
                continue
            self._log("<<", data, addr)
            pkt = decode_packet(data, addr)
            if pkt is None:
                continue
            self._contacted.add(addr[0])
            self._auto_ack(pkt)
            return pkt

    def request(self, ip, msg_type, reply_type=None, payload=b"", timeout=1.0, retries=3):
        reply_type = msg_type if reply_type is None else reply_type
        for _ in range(retries):
            self.send_to_device(ip, msg_type, payload)
            deadline = time.monotonic() + timeout
            while (left := deadline - time.monotonic()) > 0:
                pkt = self.receive(left)
                if pkt is None:
                    break
                if pkt.src[0] != ip:
                    continue
                if pkt.type == reply_type:
                    return pkt
                if pkt.type == NACK:
                    raise LoadGuardError(f"device refused request: {decode_nack(pkt.payload)[1]}")
        raise LoadGuardError(f"no reply from {ip} to request 0x{msg_type:02X}")

    def command(self, ip, msg_type, payload=b"", timeout=2.0, retries=2):
        """Send a set-command and wait for ACK. Raises on NACK or silence."""
        for _ in range(retries):
            self.send_to_device(ip, msg_type, payload)
            deadline = time.monotonic() + timeout
            while (left := deadline - time.monotonic()) > 0:
                pkt = self.receive(left)
                if pkt is None:
                    break
                if pkt.src[0] != ip:
                    continue
                if pkt.type == ACK:
                    return True
                if pkt.type == NACK:
                    code, text = decode_nack(pkt.payload)
                    raise LoadGuardError(f"NACK: {text} (code {code})")
        raise LoadGuardError(f"no ACK from {ip} for command 0x{msg_type:02X}")

    # -- high level --------------------------------------------------------------

    def discover(self, timeout=3.0, targets=None, repeats=5):
        devices = {}
        for _ in range(repeats):
            self.broadcast(GET_SERIAL, targets)
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            pkt = self.receive(left)
            if pkt is None:
                break
            ip = pkt.src[0]
            if pkt.type == GET_SERIAL and len(pkt.payload) >= 8:
                if ip not in devices:
                    devices[ip] = Device(ip, struct.unpack_from("<Q", pkt.payload)[0])
                    self.send(ip, GET_SYSTEM_ABOUT)
            elif pkt.type == GET_SYSTEM_ABOUT and len(pkt.payload) >= 36 and ip in devices:
                devices[ip].about = SystemAbout.decode(pkt.payload)
        # Ask once more for anything that did not answer the about request in time.
        for dev in devices.values():
            if dev.about is None:
                try:
                    dev.about = SystemAbout.decode(
                        self.request(dev.ip, GET_SYSTEM_ABOUT, timeout=0.7, retries=2).payload)
                except LoadGuardError:
                    pass
        return sorted(devices.values(), key=lambda d: ipaddress.IPv4Address(d.ip))

    def serial(self, ip):
        return struct.unpack_from("<Q", self.request(ip, GET_SERIAL).payload)[0]

    def system_about(self, ip):
        return SystemAbout.decode(self.request(ip, GET_SYSTEM_ABOUT).payload)

    def ip_settings(self, ip):
        return IpSettings.decode(self.request(ip, GET_IP_SETTINGS).payload)

    def measurement_type(self, ip):
        return self.request(ip, GET_MEASUREMENT_TYPE).payload[0]

    def measurement_interval(self, ip):
        return struct.unpack_from("<H", self.request(ip, GET_MEASUREMENT_INTERVAL).payload)[0]

    def server_status(self, ip):
        return decode_server_status(self.request(ip, GET_SERVER_SETTINGS).payload)

    def measurements(self, ip):
        return Measurement.decode(self.request(ip, MEASUREMENTS_ALL).payload)


# --------------------------------------------------------------------------- presentation


def fmt_ms_time(ms):
    if not ms:
        return "-"
    return datetime.fromtimestamp(ms / 1000).strftime("%d.%m.%Y %H:%M:%S")


def fmt_uptime(ms):
    s = ms // 1000
    return f"{s // 86400}:{(s // 3600) % 24:02d}:{(s // 60) % 60:02d}:{s % 60:02d}"


def to_jsonable(obj):
    if hasattr(obj, "__dataclass_fields__"):
        return {k: to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    return obj


def print_json(obj):
    print(json.dumps(to_jsonable(obj), indent=2, default=str))


def print_measurement(m, ip):
    rows = [
        ("Voltage", "V", m.voltage + [None], 2),
        ("Current", "A", m.current, 3),
        ("Active power", "kW", m.active_power, 3),
        ("Reactive power", "kVAr", m.reactive_power, 3),
        ("Apparent power", "kVA", m.apparent_power, 3),
        ("Power factor", "", m.power_factor, 3),
        ("Active energy consumed", "kWh", m.active_energy_consumed, 3),
        ("Active energy produced", "kWh", m.active_energy_produced, 3),
        ("Reactive energy consumed", "kVArh", m.reactive_energy_consumed, 3),
        ("Reactive energy produced", "kVArh", m.reactive_energy_produced, 3),
        ("Apparent energy", "kVAh", m.apparent_energy, 3),
    ]
    print(f"Load Guard {ip}   device time {fmt_ms_time(m.device_time_ms)}   "
          f"PC time {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}   "
          f"uptime {fmt_uptime(m.uptime_ms)}")
    print(f"{'':34}{'L1':>12}{'L2':>12}{'L3':>12}{'total':>12}")
    for name, unit, vals, dec in rows:
        cells = "".join(f"{'' if v is None else f'{v:.{dec}f}':>12}" for v in vals)
        print(f"{name + (f' [{unit}]' if unit else ''):34}{cells}")
    print(f"Frequency {m.frequency:.2f} Hz   Temperature {m.temperature} °C")


# --------------------------------------------------------------------------- commands


def confirm(args, summary):
    print(summary)
    if args.dry_run:
        return False
    if args.yes:
        return True
    if not sys.stdin.isatty():
        raise LoadGuardError("refusing to change settings non-interactively without --yes")
    return input("Apply? [y/N] ").strip().lower() in ("y", "yes")


def cmd_discover(c, args):
    targets = args.broadcast or None
    devices = c.discover(timeout=args.timeout, targets=targets)
    if args.json:
        return print_json(devices)
    if not devices:
        print("No Load Guard devices found. Check that this computer is on the same network/"
              "subnet, and allow incoming UDP on port 10105 in the macOS firewall.")
        return 1
    print(f"LOAD GUARD DEVICES FOUND: {len(devices)}")
    print(f"{'IP':16}{'Serial':>14}  {'MAC':19}{'SW':>6}{'HW':>6}  Uptime")
    for d in devices:
        a = d.about
        print(f"{d.ip:16}{d.serial:>14}  {a.mac if a else '-':19}{a.sw_version if a else '-':>6}"
              f"{a.hw_version if a else '-':>6}  {fmt_uptime(a.uptime_ms) if a else '-'}")
    return 0


def cmd_info(c, args):
    ip = args.ip
    about = c.system_about(ip)
    net = c.ip_settings(ip)
    master, secondary = c.server_status(ip)
    mtype = c.measurement_type(ip)
    interval = c.measurement_interval(ip)
    if args.json:
        return print_json({"ip": ip, "about": about, "network": net,
                           "chargers": {"master": master, "secondary": secondary},
                           "measurement_type": MEASUREMENT_TYPE_NAMES.get(mtype, mtype),
                           "measurement_interval_ms": interval})
    print(f"Load Guard {ip}")
    print(f"  Serial number      {about.serial}")
    print(f"  MAC address        {about.mac}")
    print(f"  Software version   {about.sw_version}")
    print(f"  Hardware version   {about.hw_version}")
    print(f"  Uptime             {fmt_uptime(about.uptime_ms)}")
    print("Network")
    if net.dhcp:
        print("  Mode               dynamic (DHCP)")
        print(f"  Address            {net.ip}")
    else:
        print("  Mode               static")
        print(f"  Address            {net.ip}")
        print(f"  Netmask            {net.netmask}")
        print(f"  Gateway            {net.gateway}")
    print("Master charger communication")
    for label, s in (("Master", master), ("Secondary", secondary)):
        st = s.settings
        if not st.enabled and label == "Secondary":
            print(f"  {label:10} disabled (no charger redundancy)")
            continue
        state = "connection established" if s.ok else "connection broken"
        print(f"  {label:10} {st.ip}:{st.port}  serial {st.serial}  -> {state}")
        print(f"  {'':10} last ack {fmt_ms_time(s.last_ack_ms)}   "
              f"last failure {fmt_ms_time(s.last_fail_ms)}")
    print("Measurement reporting")
    print(f"  Type               {MEASUREMENT_TYPE_NAMES.get(mtype, f'unknown ({mtype})')}")
    print(f"  Interval           {interval} ms")
    return 0


def cmd_measure(c, args):
    while True:
        m = c.measurements(args.ip)
        if args.json and args.watch:
            print(json.dumps(to_jsonable(m)), flush=True)  # one JSON object per line
        elif args.json:
            print_json(m)
        else:
            if args.watch:
                print("\033[2J\033[H", end="")
            print_measurement(m, args.ip)
        if not args.watch:
            return 0
        time.sleep(args.interval)


def cmd_sync_time(c, args):
    if not confirm(args, f"Set the clock of {args.ip} to this computer's time "
                         f"({datetime.now().strftime('%d.%m.%Y %H:%M:%S')})."):
        return 0
    c.command(args.ip, SYNC_TIME)
    print("Device time synchronised.")
    return 0


def cmd_set_network(c, args):
    if args.dhcp:
        payload = encode_ip_settings(True)
        summary = f"Switch {args.ip} to DHCP (dynamic IP)."
    else:
        if not (args.address and args.netmask and args.gateway):
            raise LoadGuardError("static mode needs --address, --netmask and --gateway")
        prefix = prefix_from_netmask(args.netmask)
        payload = encode_ip_settings(False, args.address, prefix, args.gateway)
        summary = (f"Set {args.ip} to static {args.address}/{prefix} gateway {args.gateway}.")
    summary += "\nThe device restarts its network; it may come back on a different address."
    if args.dry_run:
        summary += f"\npayload 0x{SET_IP_SETTINGS:02X}: {payload.hex(' ')}"
    if not confirm(args, summary):
        return 0
    c.command(args.ip, SET_IP_SETTINGS, payload)
    print("Settings successfully saved. Run 'discover' again in a few seconds to find the device.")
    return 0


def cmd_set_chargers(c, args):
    master = ServerSettings(True, args.master_ip, args.port, args.master_serial)
    if args.secondary_ip or args.secondary_serial is not None:
        if not (args.secondary_ip and args.secondary_serial is not None):
            raise LoadGuardError("--secondary-ip and --secondary-serial go together")
        secondary = ServerSettings(True, args.secondary_ip, args.port, args.secondary_serial)
    else:
        secondary = ServerSettings(False, "0.0.0.0", 0, 0)
    payload = encode_server_settings(master, secondary)
    summary = (f"Master charger    {master.ip}:{master.port} serial {master.serial}\n"
               + (f"Secondary charger {secondary.ip}:{secondary.port} serial {secondary.serial}"
                  if secondary.enabled else "Secondary charger disabled (no redundancy)"))
    if args.dry_run:
        summary += f"\npayload 0x{SET_SERVER_SETTINGS:02X}: {payload.hex(' ')}"
    if not confirm(args, summary):
        return 0
    c.command(args.ip, SET_SERVER_SETTINGS, payload)
    print("Settings successfully saved.")
    return 0


def cmd_set_reporting(c, args):
    if args.type is None and args.interval is None:
        raise LoadGuardError("give --type and/or --interval")
    if args.interval is not None and not INTERVAL_MIN <= args.interval <= INTERVAL_MAX:
        raise LoadGuardError(f"--interval must be {INTERVAL_MIN}..{INTERVAL_MAX} ms")
    parts = []
    if args.type is not None:
        parts.append(f"measurement type -> {args.type}")
    if args.interval is not None:
        parts.append(f"report interval -> {args.interval} ms")
    commands = []
    if args.type is not None:
        commands.append((SET_MEASUREMENT_TYPE, bytes([MEASUREMENT_TYPES[args.type]])))
    if args.interval is not None:
        commands.append((SET_MEASUREMENT_INTERVAL, struct.pack("<h", args.interval)))
    summary = f"{args.ip}: " + ", ".join(parts)
    if args.dry_run:
        summary += "".join(f"\npayload 0x{t:02X}: {p.hex(' ')}" for t, p in commands)
    if not confirm(args, summary):
        return 0
    for msg_type, payload in commands:
        c.command(args.ip, msg_type, payload)
    print("Settings successfully saved.")
    return 0


def cmd_monitor(c, args):
    """Print every packet (pushed measurements are acknowledged automatically)."""
    print(f"Listening on UDP {c.sock.getsockname()[1]}; Ctrl-C to stop.", file=sys.stderr)
    if args.ip:
        c.send(args.ip, GET_SERIAL)
    while True:
        pkt = c.receive(3600)
        if pkt is None:
            continue
        if args.ip and pkt.src[0] != args.ip:
            continue
        line = (f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]} {pkt.src[0]} type 0x{pkt.type:02X} "
                f"counter {pkt.counter} len {len(pkt.payload)}")
        if pkt.type == NACK:
            line += f"  NACK: {decode_nack(pkt.payload)[1]}"
        elif pkt.type == MEASUREMENTS_ALL and len(pkt.payload) >= MEASUREMENT_FORMAT.size:
            m = Measurement.decode(pkt.payload)
            line += f"  U={m.voltage} I={m.current} P={m.active_power[3]} kW"
        else:
            line += f"  {pkt.payload.hex(' ')}"
        print(line, flush=True)


def build_parser():
    p = argparse.ArgumentParser(
        prog="lgconf", description="Open-source console configurator for Etrel Load Guard.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--local-port", type=int, default=LOCAL_PORT,
                   help=f"local UDP port to listen on (default {LOCAL_PORT})")
    p.add_argument("--device-port", type=int, default=DEVICE_PORT,
                   help=f"device UDP port (default {DEVICE_PORT})")
    p.add_argument("--bind", default="0.0.0.0", help="local address to bind")
    p.add_argument("-v", "--verbose", action="store_true", help="hex-dump all packets to stderr")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, func, help_text, ip=True, write=False):
        sp = sub.add_parser(name, help=help_text, description=help_text)
        if ip:
            sp.add_argument("ip", help="Load Guard IP address")
        if write:
            sp.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
            sp.add_argument("--dry-run", action="store_true",
                            help="show what would be sent, send nothing")
        sp.set_defaults(func=func)
        return sp

    sp = add("discover", cmd_discover, "find Load Guard devices on the local networks", ip=False)
    sp.add_argument("--timeout", type=float, default=3.0, help="seconds to wait (default 3)")
    sp.add_argument("--broadcast", action="append", metavar="ADDR",
                    help="address to probe instead of all broadcast addresses (repeatable)")
    sp.add_argument("--json", action="store_true")

    sp = add("info", cmd_info, "device identity, network, charger and reporting settings")
    sp.add_argument("--json", action="store_true")

    sp = add("measure", cmd_measure, "online measurements (voltages, currents, power, energy)")
    sp.add_argument("-w", "--watch", action="store_true", help="refresh continuously")
    sp.add_argument("-n", "--interval", type=float, default=1.0, help="refresh period, s")
    sp.add_argument("--json", action="store_true")

    add("sync-time", cmd_sync_time, "set the device clock to this computer's clock", write=True)

    sp = add("set-network", cmd_set_network, "change the Load Guard IP settings", write=True)
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--dhcp", action="store_true", help="dynamic IP")
    g.add_argument("--static", action="store_true", help="static IP (needs the options below)")
    sp.add_argument("--address", help="new static IP address")
    sp.add_argument("--netmask", help="netmask, e.g. 255.255.255.0 or /24")
    sp.add_argument("--gateway", help="default gateway")

    sp = add("set-chargers", cmd_set_chargers,
             "set the master charger (and optional redundant secondary charger)", write=True)
    sp.add_argument("--master-ip", required=True)
    sp.add_argument("--master-serial", required=True, type=int)
    sp.add_argument("--secondary-ip")
    sp.add_argument("--secondary-serial", type=int)
    sp.add_argument("--port", type=int, default=CHARGER_PORT,
                    help=f"charger UDP port (default {CHARGER_PORT}, as the official tool)")

    sp = add("set-reporting", cmd_set_reporting,
             "measurement type and interval reported to the chargers", write=True)
    sp.add_argument("--type", choices=list(MEASUREMENT_TYPES), help="all | currents | none")
    sp.add_argument("--interval", type=int, help=f"ms, {INTERVAL_MIN}..{INTERVAL_MAX}")

    sp = add("monitor", cmd_monitor, "print every packet received (debugging)", ip=False)
    sp.add_argument("ip", nargs="?", help="only show packets from this device")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    for attr in ("ip", "master_ip", "secondary_ip", "address", "gateway"):
        val = getattr(args, attr, None)
        if val:
            try:
                ipaddress.IPv4Address(val)
            except ValueError:
                print(f"lgconf: invalid IPv4 address: {val}", file=sys.stderr)
                return 2
    try:
        with LoadGuardClient(args.bind, args.local_port, args.device_port, args.verbose) as c:
            return args.func(c, args) or 0
    except LoadGuardError as e:
        print(f"lgconf: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
