import os
import time
import subprocess
from zapv2 import ZAPv2
import logging
import schedule

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Log to file
file_handler = logging.FileHandler('waf_test.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Log to console
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Define the target website
TARGET_URL = 'https://example.com'

# Define ZAP API key and ZAP proxy settings
ZAP_API_KEY = 'your_zap_api_key'
ZAP_PROXY = 'http://127.0.0.1:8080'

# Initialize ZAP instance
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})

def start_zap():
    logging.info("Starting OWASP ZAP...")
    zap_start_command = '/usr/share/zaproxy/zap.sh -daemon -config api.key=' + ZAP_API_KEY
    subprocess.Popen(zap_start_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(10)  # Wait for ZAP to initialize

def run_zap_scan():
    logging.info("Running ZAP active scan...")
    scan_id = zap.ascan.scan(TARGET_URL)
    while int(zap.ascan.status(scan_id)) < 100:
        logging.info(f"ZAP scan progress: {zap.ascan.status(scan_id)}%")
        time.sleep(10)
    logging.info("ZAP scan completed")

def fetch_zap_results():
    logging.info("Fetching ZAP scan results...")
    alerts = zap.core.alerts(baseurl=TARGET_URL)
    for alert in alerts:
        logging.info(f"ZAP Alert: {alert['alert']} - Risk: {alert['risk']} - URL: {alert['url']} - Description: {alert['description']}")

def run_sqlmap():
    logging.info("Running sqlmap...")
    sqlmap_command = f"sqlmap -u {TARGET_URL} --batch --output-dir=./sqlmap_output"
    process = subprocess.Popen(sqlmap_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    logging.info(f"sqlmap output: {out.decode('utf-8')}")
    if err:
        logging.error(f"sqlmap error: {err.decode('utf-8')}")

def run_nikto():
    logging.info("Running nikto...")
    nikto_command = f"nikto -h {TARGET_URL} -output ./nikto_output.txt"
    process = subprocess.Popen(nikto_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    logging.info(f"nikto output: {out.decode('utf-8')}")
    if err:
        logging.error(f"nikto error: {err.decode('utf-8')}")

def test_waf():
    start_zap()
    run_zap_scan()
    fetch_zap_results()
    run_sqlmap()
    run_nikto()
    zap.core.shutdown()

# Schedule the WAF test to run every 10 minutes (adjust as needed)
schedule.every(10).minutes.do(test_waf)

try:
    logging.info("Starting WAF testing script...")
    while True:
        schedule.run_pending()
        time.sleep(1)
except KeyboardInterrupt:
    logging.info("Stopping WAF testing script...")
