# NetSentinel
[![GitHub release](https://img.shields.io/github/release/kaotickj/NetSentinel.svg)](https://github.com/kaotickj/NetSentinel/releases)[![GitHub license](https://img.shields.io/github/license/kaotickj/NetSentinel.svg)](https://github.com/kaotickj/NetSentinel/LICENSE)[![Python](https://img.shields.io/badge/Python-3.7%2B-blue)](https://www.python.org/)[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/kaotickj/NetSentinel)](https://github.com/kaotickj/NetSentinel)[![GitHub last commit](https://img.shields.io/github/last-commit/kaotickj/NetSentinel)](https://github.com/kaotickj/NetSentinel/commits/master)

![NetSentinel](NetSentinel.png)

---

## 🛡️ Overview

**NetSentinel** is a Python-based red team reconnaissance framework designed for stealthy internal enumeration, service discovery, and lateral movement preparation.

> 🔥 **Intended for authorized red team operations only. Use without permission is illegal and unethical.**

---

## 🔧 Features

* 🔍 **Network Discovery** via ARP and DNS with stealth scan options
* 🧠 **Hostname Resolution** via reverse DNS
* 📦 **Custom Port Scanning** with default common TCP services
* 📂 **Anonymous SMB Share Enumeration**
* 🔐 **Kerberos Reconnaissance**:

  * SPN Enumeration (Kerberoasting)
  * AS-REP Roastable Account Detection
  * Optional LDAP AD enumeration
* 📄 **Export Results** to structured JSON
* 🧩 **Modular Architecture** with extensibility in mind
* 🧠 **Threaded Execution** for fast parallelized results

---

## 🛠️ Installation

### Clone the Repository

```
git clone https://github.com/kaotickj/NetSentinel.git
cd NetSentinel
```

### Install Dependencies

Use the provided `requirements.txt`:

```
pip install -r requirements.txt
```

### Requirements

* Python 3.7+
* Modules:

  * `scapy`
  * `colorama`
  * `impacket`
  * `ldap3`

---

## Python Runtime Requirement

---

### Prerequisites

* **Python Interpreter Required:**
  The NetSentinel executables for both Windows and Linux **require a Python runtime environment installed on the target system**. This is because the GUI launcher (`NetSentinel_GUI.exe` / `NetSentinel_GUI` binary) internally runs the Python scanning script (`main.py`) by invoking `python` or `python3` through the system path.

* **Supported Python Versions:**
  It is recommended to have **Python 3.7 or newer** installed and accessible via your system's `PATH` environment variable as either `python` (Windows) or `python3` (Linux/macOS). The GUI automatically detects and uses the available Python executable.

* **Installation Instructions:**

  * **Windows:**
    Install Python from the official source: [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)
    Ensure during installation that the option **“Add Python to PATH”** is checked.

  * **Linux:**
    Most distributions ship with Python 3 installed. If not, install it using your package manager:
    For Debian/Ubuntu-based systems:

    ```bash
    sudo apt-get update
    sudo apt-get install python3
    ```

    For RedHat/CentOS/Fedora-based systems:

    ```bash
    sudo dnf install python3
    ```

* **Verification:**
  To verify Python is installed and accessible, run:

  ```bash
  python --version
  ```

  or

  ```bash
  python3 --version
  ```

  The GUI launcher will automatically detect and use the correct command.

---

### Why is Python required?

The NetSentinel GUI executable acts as a launcher that invokes the Python scanning engine (`main.py`). Therefore, the presence of a functional Python environment is mandatory for the scanning functions to execute correctly.

---

### Troubleshooting

* If the GUI fails to launch scans and shows an error related to Python not found, ensure Python is installed and the executable is included in your system's `PATH`.

* On Windows, check **Environment Variables** in System Settings to confirm Python is correctly added.

* On Linux, you may need to create a symbolic link or adjust your `PATH` if Python is installed under a non-standard name or directory.



## 🚀 Usage

### Basic Network Scan

```
python3 main.py --target 10.0.0.0/24
```

### Stealth Scan with Hostname Resolution

```
python3 main.py --target 10.0.0.0/24 --scan-type stealth --resolve-hostnames
```

### SMB Share Enumeration

```
python3 main.py --target 10.0.0.0/24 --smb-enum
```

### Kerberos Recon with Config

```
python3 main.py --target 10.0.0.0/24 --kerberos-scan
```

> Kerberos credentials and DC IP are supplied via a config file (see below).

### Custom Port Scanning

```
python3 main.py --target 192.168.1.0/24 --ports 21,22,80,443,445
```

### AS-REP Detection with User List

```
python3 main.py --target 192.168.1.0/24 --kerberos-scan --user-list ./users.txt
```

### Export Results to JSON

```
python3 main.py --target 10.0.0.0/24 --smb-enum --export-json output.json
```

---

## ⚙️ Configuration File

A config file is required for Kerberos and LDAP functionality.

Example: `NetSentinel_config.json`

```
{
  "domain": "corp.local",
  "username": "lowpriv",
  "password": "Spring2025!",
  "dc_ip": "10.0.0.5",
  "ldap_username": "ldapuser",
  "ldap_password": "ldappass"
}
```

You may also use INI format:

```
[NetSentinel]
domain = corp.local
username = lowpriv
password = Spring2025!
dc_ip = 10.0.0.5
ldap_username = ldapuser
ldap_password = ldappass
```

Place the file in the project root or use `--config <path>` (optional future enhancement).

---

## 🔎 CLI Options

| Option                | Description                                                  |
| --------------------- | ------------------------------------------------------------ |
| `--target`            | Target IP or subnet (CIDR) — **required**                    |
| `--scan-type`         | `stealth` (default) or `full` (reserved for future use)      |
| `--resolve-hostnames` | Attempt reverse DNS lookups                                  |
| `--ports`             | Comma-separated ports or `common` (default list from config) |
| `--smb-enum`          | Enable anonymous SMB share enumeration                       |
| `--kerberos-scan`     | Enable Kerberos and LDAP enumeration (requires config)       |
| `--user-list`         | Path to file of usernames for AS-REP scan                    |
| `--export-json`       | Save all output to a JSON file                               |
| `--debug`             | Enable verbose debug logging                                 |

---

## 🧪 Sample Workflows

### Full Passive Recon with Export

```
python3 main.py \
  --target 192.168.1.0/24 \
  --scan-type stealth \
  --resolve-hostnames \
  --smb-enum \
  --kerberos-scan \
  --user-list ./users.txt \
  --export-json full_recon.json
```

### Lightweight Stealth Recon

```
python3 main.py --target 192.168.1.0/24 --scan-type stealth
```

---

## 📂 Output

Scan results are structured into a dictionary with hosts as keys and include:

* Discovered IPs/MACs
* Hostnames (if resolved)
* Open ports/services
* SMB share info
* Kerberos/LDAP enumeration results
* AS-REP vulnerable accounts

Example JSON output (simplified):

```
{
  "192.168.1.10": {
    "mac": "00:11:22:33:44:55",
    "hostname": "host1",
    "ports": [80, 445],
    "smb_shares": ["\\host1\\C$", "\\host1\\Public"]
  },
  "kerberos": {
    "spns": [...],
    "asrep_vuln": [...]
  }
}
```

---

## ⚠️ Notes

* Run with administrative privileges where required.
* Always validate scope and authorization before scanning.
* Kerberos enumeration requires a valid domain user and accessible Domain Controller.
* Ensure the scanning system is on the same broadcast domain (L2) for ARP discovery.

---

## 📌 TODO & Roadmap

* Full `--scan-type full` implementation (TCP connect or SYN scans)
* Export to other formats (CSV, HTML)
* LDAP deep queries (group membership, user aging)
* Plugin support for recon modules
* Web dashboard for visualizing results

---

## 🤝 Contribution Guidelines

1. Fork the repository.
2. Create a new branch: `git checkout -b feature/your-feature-name`
3. Write and test your code.
4. Submit a pull request with detailed commit messages.

All code must follow the project’s modular architecture and use the internal `Logger`.

---

## 🐞 Reporting Issues

Open a GitHub issue and provide:

* Platform/OS details
* Command used
* Full traceback (if any)
* Expected vs actual behavior

---

## 📜 License

NetSentinel is released under the **GNU General Public License v3.0**.
See [`LICENSE`](LICENSE) for full terms.

---

## 👤 Credits

Created and maintained by **Kaotick Jay**
30-year cybersecurity veteran | Red Team Lead | Linux & PHP Specialist

> Built for red teamers who understand the value of silence and precision.
