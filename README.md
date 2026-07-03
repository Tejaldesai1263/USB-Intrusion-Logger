# USB Intrusion Logger

## Overview

USB Intrusion Logger is a Python-based defensive cybersecurity tool that monitors USB device connections in real time. It identifies connected USB devices using unique hardware IDs, compares them against a whitelist, logs unauthorized access with timestamps, and triggers alerts for suspicious activity.

This project was developed for cybersecurity learning and endpoint security research.

---

## Features

- Real-time USB device monitoring
- Detects newly connected USB devices
- Whitelist support for trusted devices
- Logs unauthorized USB connections
- Timestamped event logging
- Email alert notifications
- Audible alarm for unauthorized devices
- Export logs to CSV/Excel

---

## Technologies Used

- Python
- WMI (Windows Management Instrumentation)
- SQLite
- SMTP (Email Alerts)
- OpenPyXL
- Windows API

---

## Project Structure

```
USB-Intrusion-Logger/
│
├── usb_intrusion_logger.py
├── config.json
├── README.md
├── .gitignore
└── requirements.txt
```

---

## Installation

1. Clone the repository

```bash
git clone https://github.com/Tejaldesai1263/USB-Intrusion-Logger.git
```

2. Open the project folder

```bash
cd USB-Intrusion-Logger
```

3. Install dependencies

```bash
pip install -r requirements.txt
```

4. Run the project

```bash
python usb_intrusion_logger.py
```

---

## How It Works

1. Continuously monitors USB connections.
2. Reads the unique ID of connected devices.
3. Checks whether the device is present in the whitelist.
4. Logs all connection events.
5. Sends an email alert and plays an alarm for unauthorized devices.

---

## Future Improvements

- USB blocking support
- GUI dashboard
- Automatic PDF reports
- Cloud log storage
- Multi-user support

---

## Disclaimer

This project is intended solely for educational, research, and defensive cybersecurity purposes. It should not be used for unauthorized or malicious activities.

---

## Author

**Tejal Desai**

Cybersecurity Student | Security Research Enthusiast
