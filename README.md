# 🔍 Python Port Scanner

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A fast and simple multi-threaded port scanner built in Python. This command-line tool allows you to scan a target host (IP address or domain name) to identify open ports within a specified range.

## ✨ Features

-   **Multi-threaded Scanning:** Utilizes threading for significantly faster port scanning.
-   **Custom Port Range:** Specify the exact start and end ports for the scan.
-   **Host Validation:** Automatically resolves domain names to IP addresses.
-   **Report Generation:** Saves a clean, readable report of the scan results to a specified file.
-   **User-Friendly CLI:** Easy-to-use command-line interface powered by `argparse`.

## 📋 Requirements

-   Python 3.x
-   An active internet connection (for resolving domain names).

## 🚀 Getting Started

### Installation

1.  Clone this repository to your local machine:
    ```bash
    # Replace with your actual repository URL
    git clone https://github.com/your-username/port_scanner_project.git
    ```

2.  Navigate to the project directory:
    ```bash
    cd port_scanner_project
    ```

> **Note:** This tool uses only Python's standard libraries, so no `pip install` is necessary.

## 💻 Usage

Run the scanner from your terminal by providing a target and optional parameters for the port range and output file.

### Command-Line Arguments

-   `target`: The IP address or domain name to scan (e.g., `192.168.1.1` or `scanme.nmap.org`).
-   `-s`, `--start-port`: The first port in the scanning range.
-   `-e`, `--end-port`: The last port in the scanning range.
-   `-o`, `--output-file`: The file path to save the scan report (e.g., `reports/scan.txt`).

### Example

To scan `scanme.nmap.org` for open ports between 20 and 100 and save the results:

```bash
python src/scanner.py scanme.nmap.org -s 20 -e 100 -o reports/scan_report.txt
```

### Example Output File

After the scan completes, the content of `reports/scan_report.txt` will look similar to this:

```text
Scan Report for: scanme.nmap.org (45.33.32.156)
Time Started: 2023-10-27 10:30:00
--------------------------------------------------

[+] Port 22 is open
[+] Port 80 is open

--------------------------------------------------
Scan Finished.
Time Finished: 2023-10-27 10:30:05
```



## ✍️ Author

-   M SRIHARSHA
-   TS-RISE-CEH-2606