
# WAF Testing Script

This script is designed to test multiple websites for vulnerabilities to ensure that their Web Application Firewalls (WAFs) are functioning correctly. It uses OWASP ZAP, sqlmap, nikto, Arachni, and wpscan to perform various security scans. The script is set to run these tests every 10 minutes.

## Prerequisites

1. **Kali Linux** or another Linux distribution with the necessary tools installed.
2. **OWASP ZAP** installed on your system.
3. **Python 3** and the following Python packages:
   - `zapv2`
   - `schedule`
   - `logging`

## Installation

1. **Install OWASP ZAP:**
   ```bash
   sudo apt-get update
   sudo apt-get install zaproxy
   ```

2. **Install Python Packages:**
   ```bash
   pip install python-owasp-zap-v2.4 schedule
   ```

3. **Install sqlmap and nikto:**
   ```bash
   sudo apt-get install sqlmap nikto
   ```

4. **Install Arachni:**
   Follow the installation instructions on the [Arachni website](https://github.com/Arachni/arachni#installation).

5. **Install WPScan:**
   ```bash
   sudo gem install wpscan
   ```

## Configuration

1. **Update the target URLs:**
   Edit the `TARGET_URLS` list in the script to include the websites you want to test.

2. **Update the ZAP API key:**
   Set your OWASP ZAP API key in the `ZAP_API_KEY` variable.

## Usage

1. **Ensure ZAP is not already running:**
   Make sure there are no other instances of OWASP ZAP running.

2. **Run the Script:**
   ```bash
   python waf_test_script.py
   ```

The script will start OWASP ZAP, check its status, and then proceed to run security scans on each target URL using OWASP ZAP, sqlmap, nikto, Arachni, and wpscan. The results are logged to both the console and a log file (`waf_test.log`).

## Script Overview

### Key Functions

- `start_zap()`: Starts OWASP ZAP in daemon mode.
- `check_zap_status()`: Checks if OWASP ZAP is running and ready.
- `run_zap_scan(target_url)`: Runs an active scan using OWASP ZAP on the specified target URL.
- `fetch_zap_results(target_url)`: Fetches the results of the ZAP scan.
- `run_sqlmap(target_url)`: Runs sqlmap against the specified target URL.
- `run_nikto(target_url)`: Runs nikto against the specified target URL.
- `run_arachni(target_url)`: Runs Arachni against the specified target URL.
- `run_wpscan(target_url)`: Runs wpscan against the specified target URL.
- `test_waf()`: Orchestrates the entire testing cycle for all target URLs.

### Scheduling

The script uses the `schedule` library to run the `test_waf` function every 10 minutes. You can adjust the frequency by modifying the scheduling line in the script.

### Logging

The script logs its actions and results to both the console and a log file (`waf_test.log`). This helps in monitoring the script's progress and diagnosing any issues.

## Troubleshooting

- **ZAP is not starting**: Ensure no other instances of ZAP are running and that the correct API key is used. In some cases the ZAP port could be 8082 or different.
- **Script hangs or crashes**: Check the log file (`waf_test.log`) for detailed error messages and ensure all dependencies are installed correctly.
