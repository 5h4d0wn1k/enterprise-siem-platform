> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# Enterprise SIEM Platform

Modular **Security Information and Event Management (SIEM)** platform for
collecting, analyzing, and responding to security events — multi-source log
collection, threshold-based detection, alerting, and a real-time web dashboard.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/enterprise-siem-platform)](https://github.com/5h4d0wn1k/enterprise-siem-platform)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/enterprise-siem-platform)](https://github.com/5h4d0wn1k/enterprise-siem-platform/issues)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/enterprise-siem-platform)](https://github.com/5h4d0wn1k/enterprise-siem-platform)

A product of **Shadownik** — an enterprise-grade, extensible SIEM for defenders.

## Why

Every organization has logs; few have the pipeline to turn them into detections.
A SIEM's job is to collect events from many sources, apply deterministic rules,
and surface alerts before small anomalies become incidents. This platform does
exactly that with a clean, component-based architecture: pluggable collectors
(Windows Event Log, file-based tails), threshold-based analyzers with rules,
console and email alerters, and a live dashboard for visualization — all driven
by a single YAML configuration. Because it is modular, defenders can add custom
collectors, analyzers, and alerters without touching the core, and the bundled
test-data generator makes it easy to validate detection logic in a lab before
deployment. It is built for authorized security monitoring of systems you own.

## Features

- **Multi-source log collection** — Windows Event Log and file-based collectors
  behind an expandable collector framework
- **Real-time event analysis** — configurable threshold-based rules that detect
  security incidents
- **Flexible alerting** — console and email delivery with severity-based filtering
- **Interactive dashboard** — web UI for events, alerts, and system status with
  dark/light mode, live refresh, search, and CSV export
- **Data-flow pipeline** — `Log Sources → Collectors → Event Queue → Analyzers → Alert Queue → Alerters → Dashboard`
- **Programmatic API** — `Event`, `Alert`, `ThresholdAnalyzer`, and alerter
  classes for custom integration
- **Test framework** — built-in random/alertable test data generation
- **Robust error handling** — graceful component-failure recovery and automatic reconnection

## Quickstart

Requirements: Python 3.8+, platform support for the configured collectors.

```bash
# Linux/macOS
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python src/run_siem.py

# Windows — one-click setup
run_siem.bat
```

Then open the dashboard at `http://localhost:5000`.

CLI options (`src/run_siem.py`): `--config/-c` (default
`src/config/config.yaml`), `--log-level/-l`, `--no-dashboard/-nd`, and
`--console-only/-co`.

### Test mode

```bash
python test_siem.py --test-mode random --rate 0.5 --duration 300
run_test.bat --test-mode random --rate 0.5 --duration 300   # Windows
```

(`--test-mode` in `random`, `alertable`, `both`; `--rate` events/sec;
`--duration` seconds, `0` = indefinite.)

## Configuration

YAML files in `src/config/` — the main file is `config.yaml`. Sections:
`General`, `Collectors`, `Analyzers`, `Alerters`, `Dashboard`.

## Documentation

- [User Guide](docs/README.md) — comprehensive user and administrator guide
- [Developer Guide](docs/DEVELOPER_GUIDE.md) — extending the platform
- [CLI Reference](docs/CLI_REFERENCE.md) · [Config Guide](docs/CONFIG_GUIDE.md) ·
  [Dashboard API](docs/DASHBOARD_API.md) · [AI Modules](docs/AI_MODULES.md) ·
  [AI Enhancement Plan](docs/AI_ENHANCEMENT_PLAN.md) · [Quick Reference](docs/QUICK_REFERENCE.md)

## Project structure

- `src/collectors/` — log collection modules (file, Windows Event Log)
- `src/analyzers/` — detection and correlation rules
- `src/alerting/` — console and email alerters
- `src/dashboard/` — web interface
- `examples/` — API usage and custom extensions

## Legal & authorized use

For **educational and authorized security monitoring** of systems you own or in
your laboratory. See [ETHICS.md](ETHICS.md), [SCOPE.md](SCOPE.md),
[SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).