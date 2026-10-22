# Etrel Load Guard UDP protocol

Reconstructed from `LoadGuardConfigurator.exe` v1.4 (SHA-256
`afd24370d3d73860dd362d70a8c242b3a1a1ef6df88469c4965e053920686f0d`, Qt 5.9.1 /
MinGW 32-bit, built 2017-12-29) by static analysis with REA + Ghidra 12.1.4, then checked
against a real Load Guard (software version 10, hardware version 257) with read-only
requests. Function addresses refer to that binary.

Status legend: **observed** = read directly from the code; **verified** = also matched
real device traffic; **inferred** = meaning derived from usage or from real readings;
**unknown** = parsed but not used.

## Transport

| Item | Value | Source |
|---|---|---|
| Device port | UDP **10102** (`0x2776`) | `0x406340` → `0x409220` |
| Configurator port | UDP **10105** (`0x2779`), bound on `0.0.0.0` | `0x409220` |
| Byte order | **little-endian** (verified) | `setByteOrder(1)` in every sender; `1` is `QDataStream::LittleEndian` |
| Discovery | `0x7F` to `255.255.255.255:10102`, sent 5× from every local IPv4 address (source port 10105) | `0x416530`, `0x401bc0` |

While discovery runs, packets from any address are accepted. Afterwards only packets
from the selected device's IP are processed (`0x4132d0`, flag `0x43e059`).

## Header (11 bytes, every packet)

```
offset size type   field
0      8    int64  timestamp, ms since Unix epoch (sender's clock)
8      2    int16  packet counter (incremented per packet sent)
10     1    int8   message type
```

All fields are little-endian. The payload follows the header directly. Its length is
`datagram length - 11` (`0x408da0`, receive check `len > 10`). Example: a real
discovery reply (serial anonymised) `4A A4 D4 64 A1 01 00 00 | 02 47 | 7F | 4E 61 BC 00 00 00 00 00`
is timestamp 1792693019722 ms (the device's clock), counter 0x4702, type `0x7F`, serial 12345678.

## Requests sent by the configurator

Payload is empty unless listed.

| Type | Name (from moc) | Payload | Used by GUI | Source |
|---|---|---|---|---|
| `0x11` | getMeasurementsAll | – | every 1 s | `0x4129b0` |
| `0x22` | getSettings (IP) | – | on connect | `0x40ac20` |
| `0x23` | getMeasurementType | – | on connect | `0x40a1c0` |
| `0x24` | getServerSettings | – | every 1 s and every 250 ms | `0x40ad90` |
| `0x25` | getMeasurementSendingInterval | – | on connect | `0x40a520` |
| `0x7C` | getHwVersion | – | no | `0x40aaa0` |
| `0x7D` | getMacAddress | – | no | `0x40b080` |
| `0x7E` | getSystemAbout | – | for each discovered device | `0x412b20` |
| `0x7F` | requestSerialNumber | – (broadcast = discovery) | discovery, on connect | `0x409b40`, `0x416530` |
| `0xA1` | sendNewTimestamp | – (device takes the header timestamp) | "Sync device time" | `0x4099d0` |
| `0xA2` | sendNewSystemSettings | see below (13 B) | "Save changes" (IP) | `0x40a690` |
| `0xA3` | setMeasurementType | `u8`: 0 none, 1 all, 2 currents | "Save changes" (charger) | `0x40a030` |
| `0xA4` | sendNewServerSettings | 2 × SERVER_SETTINGS (30 B) | "Save changes" (charger) | `0x40b200` |
| `0xA5` | setMeasurementSendingInterval | `int16` ms (GUI range 100–5000, step 50) | "Save changes" (charger) | `0x40a390` |

### `0xA2` IP settings (13 bytes)

```
DHCP:    u8 1, then 12 × 0x00
Static:  u8 0, u32 ip, u32 netmask, u32 gateway      (little-endian like everything else)
```

`192.168.1.10` is sent as `0A 01 A8 C0` and a /24 netmask as `00 FF FF FF`. The GUI
turns the netmask text into a prefix length by summing bits per octet (`0x417980`),
then writes the four mask bytes one by one (`0x40a690`, jump table at `0x430294`); the
result equals the little-endian u32 of the netmask. The `0x22` reply uses the same
13-byte layout (**verified**: a device configured as 192.168.1.249/24 via 192.168.1.1
answers `00 F9 01 A8 C0 00 FF FF FF 01 01 A8 C0`).

### `0xA4` server (master charger) settings (30 bytes)

Two consecutive 15-byte blocks: server 1 (master charger), then server 2 (secondary/redundant).

```
SERVER_SETTINGS (15 B)        (0x409080 write / 0x4090f0 read)
  u8   enabled
  u32  ip
  u16  udp port         (GUI always sends 10105)
  u64  charger serial number
```

A disabled server is sent as 15 zero bytes. The GUI always sends server 1 as enabled
and enables server 2 when "Charger redundancy supported" is ticked (`0x405fb0`). In the
`0x24` reply a real device reported its unused second server as `00` followed by
fourteen `FF` bytes, with zero timestamps and `ok = 0`.

## Replies and unsolicited messages from the device

| Type | Meaning | Payload | Configurator reaction | Source |
|---|---|---|---|---|
| `0x01` | ACK | – | "Settings successfully saved." | case 1 |
| `0x02` | NACK | `int64` ts, `int16` counter, `int16` error code | shows `<time> NACK: <text>` | case 2 |
| `0x03` | boot announcement | SYSTEM_ABOUT (≥30 B) | (server mode only) ack `0x04` + time sync | case 3 |
| `0x11` | all measurements | MEASUREMENT_ALL (430 B) | ack `0x14` | case 0x11 |
| `0x12` | currents only | MEASUREMENT_CURRENTS (24 B) | ack `0x13` | case 0x12 |
| `0x19` | energy buffer | `u8 n`, `int64 ts`, n × (`int16`, `int16`) | ack `0x1A` | case 0x19 |
| `0x22` | IP settings | `u8 dhcp`, `u32 ip`, `u32 netmask`, `u32 gateway` | fills IP form | case 0x22 |
| `0x23` | measurement type | `u8` | radio buttons | case 0x23 |
| `0x24` | server settings | 2 × (SERVER_SETTINGS, `int64 lastAck`, `int64 lastFail`, `u8 ok`) = 64 B | charger status | case 0x24 |
| `0x25` | measurement interval | `u16` ms | spin box | case 0x25 |
| `0x70` | hardware info | `int64` serial, `int16` hw version, MAC (6 B) | – | case 0x70 |
| `0x7C` | hardware version | `int16` | – | case 0x7c |
| `0x7D` | MAC address | MAC (6 B) | – | case 0x7d |
| `0x7E` | system about | SYSTEM_ABOUT (36 B) | device list text, uptime | case 0x7e |
| `0x7F` | serial number | `u64` | adds device to list / title | case 0x7f |

All cases are in `receiveProcess` (`0x4132d0`). The jump table at `0x4312ac` is
indexed by the type byte.

### Acknowledgements the configurator sends back

| Type | For | Payload | Source |
|---|---|---|---|
| `0x04` | `0x03` boot | `int64` ts, `int16` counter of the boot packet, `int64` own id | `0x409cb0` |
| `0x13` | `0x12` currents | `int64` ts, `int16` counter of the received packet | `0x409690` |
| `0x14` | `0x11` measurements | `int64` ts, `int16` counter of the received packet | `0x4094e0` |
| `0x1A` | `0x19` energy buffer | `u8` record count, `int64` buffer timestamp | `0x409330` |

### NACK error codes (`0x412ca0`)

| Code | Text |
|---|---|
| 0 | Received error unknown |
| 1 | Received packet too short |
| 2 | MAC address already set |
| 3 | MAC address is not valid |
| 4 | Serial number is already set |
| 5 | Serial number is not valid |
| 6 | IP settings are not valid |
| 7 | Settings for both servers are same |
| 8 | Measurement type is not valid |
| 9 | Reading of register is not allowed |
| 10 | Writing of register is not allowed |
| 11 | Register is not 32bit or reading of register is not allowed |
| 12 | Errors on SPI communication with AFE |
| 13 | UDP message type not valid |
| 14 | AFE is not calibrated yet |
| 15 | Server already enabled |
| 16 | Server list is full |
| 17 | Server is not on list |
| 18 | Hardware version is already set |
| 19 | Hardware version is not valid |
| 20 | Calibration was already started |
| 21 | Calibration was already ended |
| 22 | Server UDP port is not valid |
| 23 | Measurement sending interval is too low |
| 24 | Measurement sending interval is too high |

## Structures

### SYSTEM_ABOUT (36 bytes, `0x408fb0`)

```
int64  uptime, ms                (inferred: shown as "Up time" D:hh:mm:ss, 0x406500)
int64  serial number             (observed: stored as the device serial)
u16    hardware version          (observed: "HWv:")
u16    unknown
u16    software version          (observed: "SWv:")
6 B    MAC as a little-endian 48-bit value (GUI prints it most-significant byte first,
       hex, ':'-separated; verified against the device's ARP entry)
int64  unknown
```

### MEASUREMENT_ALL (430 bytes, `0x408390`, display in `0x403b70`)

| Wire offset | Type | Count | Field | Scale / unit |
|---|---|---|---|---|
| 0 | int64 | 1 | uptime | ms |
| 8 | int64 | 1 | device time | ms since epoch ("Device time") |
| 16 | u16 | 3 | voltage L1–L3 | ÷100 → V |
| 22 | int32 | 4 | current L1–L3, total | ÷1000 → A |
| 38 | int32 | 4 | active power L1–L3, total | ÷1000 → kW |
| 54 | int32 | 4 | reactive power L1–L3, total | ÷1000 → kVAr |
| 70 | int32 | 4 | apparent power L1–L3, total (**inferred**) | ÷1000 → kVA |
| 86 | int32 | 1 | unknown | – |
| 90 | int16 | 4 | power factor L1–L3, total (**inferred**) | ÷1000 |
| 98 | int16 | 1 | frequency | ÷100 → Hz |
| 100 | int16 | 1 | temperature | °C |
| 102 | int64 | 4 | active energy consumed (forward) L1–L3, total | ÷10⁶ → kWh |
| 134 | int64 | 4 | active energy produced (reverse) L1–L3, total | ÷10⁶ → kWh |
| 166 | int64 | 4 | reactive energy consumed (forward) L1–L3, total | ÷10⁶ → kVArh |
| 198 | int64 | 4 | reactive energy produced (reverse) L1–L3, total | ÷10⁶ → kVArh |
| 230 | int64 | 4 | apparent energy L1–L3, total (**inferred**) | ÷10⁶ → kVAh |
| 262 | int64 | 17 | unknown | – |
| 398 | int16 | 16 | unknown | – |

The scales are **observed** from the GUI's fixed-point formatter (`0x417280`,
`0x4175e0`, `0x416b20`), which takes the number of decimals and appends the unit
string. The field names come from the label each value is written to.

The GUI never shows the **inferred** rows. On a real reading they satisfy S ≈ V·I and
PF ≈ P/S for every phase (e.g. 231.42 V × 1.631 A = 377 VA vs. 378 reported; 147 W / 378 VA
= 0.389 vs. 0.391), and the per-phase apparent energies add up to the total. The
GUI labels the 4th current "total", but on a real device it is not the arithmetic
sum of L1–L3 (1.64 A vs. 4.46 A), so it is probably the neutral or vector-sum current.

### MEASUREMENT_CURRENTS (24 bytes, `0x408cc0`)

`int64` timestamp, then four `int32` currents. Units are presumably the same as
MEASUREMENT_ALL (not displayed by the GUI).

## Factory and calibration commands (not exposed by the open-source tool)

These exist in `lg::LoadGuard` but no GUI element calls them in v1.4. They provision
or recalibrate the meter front-end and could damage a working device:

| Type | Name | Payload |
|---|---|---|
| `0xFF` | setSerialNumberOnLG | `u64` serial |
| `0xFD` | setMacAddress | MAC (6 B) |
| `0x62` | calibrationLoadFromLg (reply `0x62` = 108 B calibration block) | – |
| `0x64` | calibrationReadRegister16bit | `u16` address |
| `0x65` | calibrationReadRegister32bit | `u16` address |
| `0xE0` | calibrationStart | not analysed |
| `0xE1` | calibrationEnd | – |
| `0xE3` | calibrationSaveToLg | not analysed |
| `0xE6` | calibrationWriteRegister16bit | `u16` address, `u16` value |
| `0xE7` | calibrationCopyAfeToEeprom | – |

## Validation against a real device

Read-only requests (`0x7F`, `0x7E`, `0x22`, `0x23`, `0x24`, `0x25`, `0x11`) were sent to
a production Load Guard. Every reply had exactly the payload length the configurator
expects (8, 36, 13, 1, 64, 2 and 430 bytes) and decoded to coherent values: the device's
own address and gateway, the MAC from the ARP table, a master charger on port 10105 with a
last-ACK time seconds old, mains voltages of 229–232 V at 50.0 Hz. Anonymised payloads are
in `tests/fixtures/real_device.json`.

The write commands (`0xA1`–`0xA5`) were **not** sent to real hardware; their encoding
is taken from the configurator code and checked in unit tests and against the simulator.

## macOS note

Without the Local Network permission for the terminal app, macOS rejects `sendto()` to
a LAN host with `EHOSTUNREACH` until that host has sent a datagram to the same socket,
and a socket that was rejected stops receiving. Broadcasts are not affected. `lgconf`
therefore broadcasts a `0x7F` probe and waits for the device's reply before its first
unicast to a LAN address (observed on macOS 27; harmless elsewhere and skipped off-LAN).

## Configurator behaviour worth copying

- After `0xA2` (IP change) the GUI shows "Program will now automatically restart",
  waits 2 s and re-runs discovery, because the device may come back on a new address.
- `0x11` replies are acknowledged with `0x14` even when they answer a request.
- Device time sync (`0xA1`) has no payload; the device uses the header timestamp.
