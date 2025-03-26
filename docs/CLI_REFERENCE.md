# Command Line Interface Reference

This document provides detailed information about the command-line options available for the Enterprise SIEM Platform.

## run_siem.py

The main script to run the SIEM platform.

```
python src/run_siem.py [options]
```

### Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--config`, `-c` | Path to configuration file | `data/configs/config.yaml` | `--config custom_config.yaml` |
| `--log-level`, `-l` | Set logging level | `INFO` | `--log-level DEBUG` |
| `--no-dashboard` | Disable the web dashboard | Dashboard enabled | `--no-dashboard` |
| `--console-only` | Only use console for alerts | All configured alerters | `--console-only` |

### Examples

Basic usage:
```bash
python src/run_siem.py
```

With custom configuration:
```bash
python src/run_siem.py --config configs/production.yaml
```

Debug mode with console alerts only:
```bash
python src/run_siem.py --log-level DEBUG --console-only
```

Run without dashboard:
```bash
python src/run_siem.py --no-dashboard
```

## test_siem.py

Script for testing the SIEM platform with generated data.

```
python test_siem.py [options]
```

### Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--config`, `-c` | Path to configuration file | `data/configs/config.yaml` | `--config test_config.yaml` |
| `--log-level`, `-l` | Set logging level | `INFO` | `--log-level DEBUG` |
| `--test-mode`, `-m` | Test mode (random, alertable, both) | `random` | `--test-mode alertable` |
| `--rate`, `-r` | Events per second | `1.0` | `--rate 0.5` |
| `--duration`, `-d` | Test duration in seconds (0 = infinite) | `600` | `--duration 300` |
| `--dashboard`, `-w` | Enable or disable dashboard | Enabled | `--dashboard false` |

### Examples

Generate random events at default rate and duration:
```bash
python test_siem.py
```

Generate alertable events for 5 minutes:
```bash
python test_siem.py --test-mode alertable --duration 300
```

Generate both random and alertable events at a slower rate:
```bash
python test_siem.py --test-mode both --rate 0.5
```

Run indefinitely (until manually stopped):
```bash
python test_siem.py --duration 0
```

## run_siem.bat (Windows)

Batch file for running the SIEM platform on Windows systems.

```
run_siem.bat [options]
```

### Options

Supports all options from `run_siem.py`:

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--config` | Path to configuration file | `data/configs/config.yaml` | `--config custom_config.yaml` |
| `--log-level` | Set logging level | `INFO` | `--log-level DEBUG` |
| `--no-dashboard` | Disable the web dashboard | Dashboard enabled | `--no-dashboard` |
| `--console-only` | Only use console for alerts | All configured alerters | `--console-only` |

### Examples

Basic usage:
```batch
run_siem.bat
```

With custom configuration:
```batch
run_siem.bat --config configs/windows.yaml
```

## run_test.bat (Windows)

Batch file for testing the SIEM platform on Windows systems.

```
run_test.bat [options]
```

### Options

Supports all options from `test_siem.py`:

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--test-mode` | Test mode (random, alertable, both) | `random` | `--test-mode alertable` |
| `--rate` | Events per second | `1.0` | `--rate 0.5` |
| `--duration` | Test duration in seconds (0 = infinite) | `600` | `--duration 300` |
| `--config` | Path to configuration file | `data/configs/config.yaml` | `--config test_config.yaml` |
| `--log-level` | Set logging level | `INFO` | `--log-level DEBUG` |
| `--dashboard` | Enable or disable dashboard | Enabled | `--dashboard false` |

### Examples

Basic usage:
```batch
run_test.bat
```

Generate alertable events for 10 minutes:
```batch
run_test.bat --test-mode alertable --duration 600
```

## Environment Variables

The SIEM platform also supports configuration through environment variables:

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `SIEM_CONFIG_PATH` | Path to configuration file | `data/configs/config.yaml` | `SIEM_CONFIG_PATH=configs/custom.yaml` |
| `SIEM_LOG_LEVEL` | Logging level | `INFO` | `SIEM_LOG_LEVEL=DEBUG` |
| `SIEM_DASHBOARD_ENABLED` | Enable/disable dashboard | `true` | `SIEM_DASHBOARD_ENABLED=false` |
| `SIEM_DASHBOARD_PORT` | Dashboard port | `5000` | `SIEM_DASHBOARD_PORT=8080` |
| `SIEM_EMAIL_SERVER` | SMTP server for email alerts | From config | `SIEM_EMAIL_SERVER=smtp.example.com` |
| `SIEM_EMAIL_PORT` | SMTP port | From config | `SIEM_EMAIL_PORT=587` |
| `SIEM_EMAIL_USERNAME` | SMTP username | From config | `SIEM_EMAIL_USERNAME=alerts@example.com` |
| `SIEM_EMAIL_PASSWORD` | SMTP password | From config | `SIEM_EMAIL_PASSWORD=password123` |

### Usage with Environment Variables

Linux/macOS:
```bash
export SIEM_LOG_LEVEL=DEBUG
export SIEM_DASHBOARD_PORT=8080
python src/run_siem.py
```

Windows (Command Prompt):
```batch
set SIEM_LOG_LEVEL=DEBUG
set SIEM_DASHBOARD_PORT=8080
run_siem.bat
```

Windows (PowerShell):
```powershell
$env:SIEM_LOG_LEVEL = "DEBUG"
$env:SIEM_DASHBOARD_PORT = "8080"
.\run_siem.bat
```

## Return Codes

The SIEM platform scripts return the following exit codes:

| Code | Description |
|------|-------------|
| 0 | Success - normal termination |
| 1 | General error |
| 2 | Configuration error |
| 3 | Initialization error |
| 4 | Runtime error |
| 130 | Terminated by keyboard interrupt (Ctrl+C) |

## Logging

Log levels available for `--log-level`:

| Level | Description |
|-------|-------------|
| `DEBUG` | Detailed debug information |
| `INFO` | General information messages |
| `WARNING` | Warning messages |
| `ERROR` | Error messages |
| `CRITICAL` | Critical errors |

Logs are written to:
- Console (stderr)
- File: `data/logs/siem.log`

## Advanced Usage

### Running as a Service

#### Windows (using NSSM)

```batch
# Install as service
nssm install SIEMPlatform "C:\path\to\python.exe" "C:\path\to\enterprise-siem-platform\src\run_siem.py"
nssm set SIEMPlatform AppDirectory "C:\path\to\enterprise-siem-platform"
nssm set SIEMPlatform AppParameters "--config=configs/production.yaml"
nssm start SIEMPlatform
```

#### Linux (using Systemd)

Create a file `/etc/systemd/system/siem-platform.service`:

```ini
[Unit]
Description=Enterprise SIEM Platform
After=network.target

[Service]
User=siem
WorkingDirectory=/path/to/enterprise-siem-platform
ExecStart=/path/to/venv/bin/python src/run_siem.py --config configs/production.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Then enable and start the service:

```bash
sudo systemctl enable siem-platform.service
sudo systemctl start siem-platform.service
``` 