# Etrel Load Guard Configurator for macOS, Linux and Windows (open source)

`lgconf` is an open-source, cross-platform replacement for Etrel's Windows-only
[**Load Guard Configurator 1.4**](https://etrel.atlassian.net/wiki/spaces/EKC/pages/3485632839/Load+Guard+Configuration+software). Etrel Load Guard is the energy meter that feeds the
dynamic load management (load balancing) of Etrel EV chargers. With `lgconf` you can:

- discover Load Guard devices on your network;
- read live measurements: voltage, current, power and energy per phase;
- change the network settings, master charger and measurement reporting.

It is a single Python 3 file with no dependencies, so it runs anywhere Python does,
including Apple Silicon Macs where the original Qt/Windows tool does not.

```sh
git clone https://github.com/XavierGeerinck/etrel-load-guard-configurator.git
cd etrel-load-guard-configurator
```

> Unofficial and not affiliated with Etrel. "Etrel" and "Load Guard" are trademarks
> of their owner. The protocol was reverse engineered for interoperability; no Etrel
> code or assets are included.

## Quick start

```sh
python3 lgconf.py discover
```
```
LOAD GUARD DEVICES FOUND: 1
IP                      Serial  MAC                    SW    HW  Uptime
192.168.1.249         12345678  02:00:00:00:00:01      10   257  184:08:23:49
```

```sh
python3 lgconf.py info 192.168.1.249           # identity, network, chargers, reporting
python3 lgconf.py measure 192.168.1.249 -w     # live measurements, refreshed every second
```
```
Load Guard 192.168.1.249   device time 22.10.2026 20:22:38   PC time 22.10.2026 20:30:30   uptime 184:08:24:02
                                            L1          L2          L3       total
Voltage [V]                             232.32      228.98      229.05
Current [A]                              1.630       1.635       1.427       1.800
Active power [kW]                        0.146       0.227       0.218       0.593
...
Frequency 50.02 Hz   Temperature 24 °C
```

Add `--json` to `discover`, `info` or `measure` for machine-readable output.
`measure --watch --json` prints one JSON object per line.

## Changing settings

Every write shows what it will do and asks for confirmation. Use `--dry-run` to see
the exact bytes without sending, and `--yes` to skip the prompt in scripts.

| Official GUI | lgconf |
|---|---|
| Sync device time | `lgconf sync-time IP` |
| Load Guard communication settings: dynamic | `lgconf set-network IP --dhcp` |
| Load Guard communication settings: static | `lgconf set-network IP --static --address A --netmask 255.255.255.0 --gateway G` |
| Master charger IP + serial | `lgconf set-chargers IP --master-ip A --master-serial N` |
| Charger redundancy (charger 2) | `... --secondary-ip B --secondary-serial M` (omit to disable) |
| Measurements: All / Currents | `lgconf set-reporting IP --type all` / `--type currents` |
| Measurements report interval (100–5000 ms) | `lgconf set-reporting IP --interval 750` |

Like the official tool, a network change makes the device restart its network, so
run `discover` again afterwards. The factory and calibration commands found in the
original program (setting serial or MAC, meter calibration) are deliberately not
exposed.

`lgconf monitor [IP]` prints every packet it receives, and `-v` hex-dumps all traffic
for any command.

## Requirements and macOS notes

- Python 3.8 or newer (`python3 --version`); nothing to install.
- The tool listens on **UDP 10105** and talks to devices on **UDP 10102**, the same as
  the official configurator, so don't run both at once (or use `--local-port`).
- The computer has to be on the same network segment as the Load Guard for discovery.
  If you know the address you can talk to it directly by IP.
- If the macOS firewall is on, allow incoming connections for Python when asked.
- macOS may block unicast to LAN devices for apps without the *Local Network*
  permission (System Settings › Privacy & Security › Local Network). lgconf works
  around this automatically by broadcasting first, but granting your terminal app
  the permission avoids the extra step.

## Testing without a device

```sh
python3 tools/lgsim.py --port 11102 &                  # simulated Load Guard
python3 lgconf.py --device-port 11102 info 127.0.0.1
python3 -m unittest discover -s tests                  # protocol + end-to-end tests
```

The simulator answers every request lgconf sends. The unit tests check byte layouts
against hand-written vectors and against replies captured from a real Load Guard
(anonymised, in `tests/fixtures/`).

## Status

- **Verified on a real Load Guard** (SW 10 / HW 257): discovery, device info, network
  settings, charger status, reporting settings and live measurements.
- **Not yet exercised on hardware:** the write commands. Their encoding comes straight
  from the official configurator's code and passes the tests and simulator, but try
  `--dry-run` first and keep the official tool nearby the first time.

## Official Etrel documentation

- [Load Guard Configuration software](https://etrel.atlassian.net/wiki/spaces/EKC/pages/3485632839/Load+Guard+Configuration+software):
  the official Windows configurator that this tool replaces, and how Etrel describes
  the Load Guard setup.
- [INCH user manual](https://etrel.atlassian.net/wiki/spaces/EKC/pages/3371074217/INCH+User+manual):
  setting up the INCH chargers that the Load Guard reports to, including load management.
- [All INCH firmware versions](https://etrel.atlassian.net/wiki/spaces/EKC/pages/5064097900/All+INCH+Firmware+versions):
  charger firmware releases and release notes.

## How it was reverse engineered

The official `LoadGuardConfigurator.exe` (32-bit Qt 5.9 / MinGW) was analysed with
[REA](https://github.com/morluto/rea) on Ghidra 12.1.4:

- decompiled all 180 application functions;
- resolved Qt's overloaded `QDataStream` operators from the import table, which gave
  exact field widths;
- mapped the moc signal/slot tables to names;
- rebuilt the UI from `setupUi`/`retranslateUi` to tie each value to its label.

The byte order and the unlabelled measurement fields were then confirmed against a
live device. The full message reference, with function addresses, is in
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## License

MIT, see [LICENSE](LICENSE).
