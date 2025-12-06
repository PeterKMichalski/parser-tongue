# Parser Tongue 🐍

**Parser Tongue** is a modular, CLI-based forensic parsing tool written in Python. It provides a centralized engine for parsing various log files into standardized CSVs and performing static analysis on suspicious strings (such as obfuscated PowerShell).

It is designed for Security Operations and Incident Response analysts who need to quickly normalize data or de-obfuscate commands without executing them.

## Core Features

- **Modular Architecture:**, Add new parsers simply by dropping a Python file into the directory.
- **Smart Auto-Detection:**, Automatically identifies the correct parser for a file or string based on content signatures.
- **Batch Processing:**, Uses multiprocessing to rapidly parse entire directories of logs.
- **Standardized Output:**
  - **File Parsers:**, Produce CSVs with a consistent ,`Timestamp_UTC`, column for easy timeline correlation.
  - **String Parsers:**, Produce JSON output with beautified code and extracted IOCs (URLs, IPs, Files).
- **Safety First:**, All string analysis (including PowerShell) is performed statically. No code is ever executed.

## Supported Artifacts

**Log Parsers (Output: CSV)**

- **Web Logs:**, Apache Access Logs, IIS Logs.
- **System:**, Linux Auth Logs (,`/var/log/auth.log`,).
- **Email:**, ,`.eml`, (Standard), ,`.msg`, (Outlook), ,`.pst`, (Outlook Archives).
- **Data:**, JSON and JSONL (with automatic flattening of nested structures).

**String Parsers (Output: JSON)**

- **PowerShell Static Analyzer:**, Beautifies scripts, resolves variables, simplifies concatenation, and extracts indicators.
- **PowerShell Advanced Analyzer (Experimental):**, Attempts deeper variable resolution for complex obfuscation.
- **Base64:**, Automatic detection and decoding.

## Installation

1. git clone [https://github.com/your-username/parser-tongue.git](https://github.com/your-username/parser-tongue.git)
cd parser-tongue
2. pip install pandas extract-msg libpff-python

## Usage

### 1. File Parsing (Logs)

**Parse a single file:**

python parsertongue.py --file /path/to/logfile.log

_The tool will auto-detect the format and ask for confirmation._

**Parse an entire directory (Batch Mode):**

python parsertongue.py --dir /path/to/logs/ --output /path/to/results/

### 2. String Analysis (De-obfuscation)

**Analyze a string directly:**

python parsertongue.py --string "powershell.exe -enc JABh..."

**Analyze a string from a file (Recommended for long scripts):**

python parsertongue.py --string-file /path/to/malicious_script.ps1

### 3. Managing Parsers

**List all available parsers:**

python parsertongue.py --list-parsers
python parsertongue.py --list-string-parsers

**Create a new parser from a template:**

python parsertongue.py --new-parser "My Custom Log Parser"

## Disclaimer

The **PowerShell Static Analyzer** is a best-effort tool. While it is designed to be safe (no execution), complex obfuscation can lead to incomplete results. Always validate findings manually.

