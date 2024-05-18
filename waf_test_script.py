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
TARGET_URL = 'https://example.com'  # Ensure this URL is correct and reachable

# Define ZAP API key and ZAP proxy settings
ZAP_API_KEY = 'your_zap_api_key'
ZAP_PROXY = 'http://127.0.0.1:8080'

# Initialize ZAP instance
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})

def start_zap():
    logger.info("Starting OWASP ZAP...")
    zap_start_command = ['/usr/share/zaproxy/zap.sh', '-daemon', '-config', f'api.key={ZAP_API_KEY}']
    subprocess.Popen(zap_start_command)
    logger.info("OWASP ZAP started, waiting for initialization...")

def check_zap_status():
    for _ in range(30):  # Retry for 300 seconds
        try:
            version = zap.core.version
            logger.info(f"ZAP is running. Version: {version}")
            return True
        except Exception as e:
            logger.warning(f"ZAP is not yet running: {e}")
            time.sleep(10)
    logger.error("ZAP did not start within the expected time.")
    return False

def run_zap_scan():
    logger.info("Running ZAP active scan...")
    try:
        # Log the URL being scanned
        logger.info(f"Starting scan for URL: {TARGET_URL}")
        response = zap.urlopen(TARGET_URL)
        time.sleep(2)  # Wait for the URL to be accessed

        # Start the scan
        scan_id = zap.ascan.scan(TARGET_URL)
        logger.info(f"Received scan ID: {scan_id}")

        if scan_id.isdigit():
            while int(zap.ascan.status(scan_id)) < 100:
                logger.info(f"ZAP scan progress: {zap.ascan.status(scan_id)}%")
                time.sleep(10)
            logger.info("ZAP scan completed")
        else:
            logger.error(f"Invalid scan ID: {scan_id}")
    except Exception as e:
        logger.error(f"Error running ZAP active scan: {e}")

def fetch_zap_results():
    logger.info("Fetching ZAP scan results...")
    try:
        alerts = zap.core.alerts(baseurl=TARGET_URL)
        for alert in alerts:
            logger.info(f"ZAP Alert: {alert['alert']} - Risk: {alert['risk']} - URL: {alert['url']} - Description: {alert['description']}")
    except Exception as e:
        logger.error(f"Error fetching ZAP results: {e}")

def run_sqlmap():
    logger.info("Running sqlmap...")
    sqlmap_command = f"sqlmap -u {TARGET_URL} --batch --output-dir=./sqlmap_output"
    process = subprocess.Popen(sqlmap_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = process.communicate(timeout=300)  # 5-minute timeout
        logger.info(f"sqlmap output: {out.decode('utf-8')}")
        if err:
            logger.error(f"sqlmap e
