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

# Define the target websites
TARGET_URLS = [
    'https://example.com',
    'https://example.org',
    'https://example.net'
]

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

def run_zap_scan(target_url):
    logger.info(f"Running ZAP active scan for {target_url}...")
    try:
        zap.urlopen(target_url)
        time.sleep(2)  # Wait for the URL to be accessed

        scan_id = zap.ascan.scan(target_url)
        logger.info(f"Received scan ID for {target_url}: {scan_id}")

        if scan_id.isdigit():
            while int(zap.ascan.status(scan_id)) < 100:
                logger.info(f"ZAP scan progress for {target_url}: {zap.ascan.status(scan_id)}%")
                time.sleep(10)
            logger.info(f"ZAP scan completed for {target_url}")
        else:
            logger.error(f"Invalid scan ID for {target_url}: {scan_id}")
    except Exception as e:
        logger.error(f"Error running ZAP active scan for {target_url}: {e}")

def fetch_zap_results(target_url):
    logger.info(f"Fetching ZAP scan results for {target_url}...")
    try:
        alerts = zap.core.alerts(baseurl=target_url)
        for alert in alerts:
            logger.info(f"ZAP Alert for {target_url}: {alert['alert']} - Risk: {alert['risk']} - URL: {alert['url']} - Description: {alert['description']}")
    except Exception as e:
        logger.error(f"Error fetching ZAP results for {target_url}: {e}")

def run_sqlmap(target_url):
    logger.info(f"Running sqlmap for {target_url}...")
    sqlmap_command = f"sqlmap -u {target_url} --batch --output-dir=./sqlmap_output"
    process = subprocess.Popen(sqlmap_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = process.communicate(timeout=300)  # 5-minute timeout
        logger.info(f"sqlmap output for {target_url}: {out.decode('utf-8')}")
        if err:
            logger.error(f"sqlmap error for {target_url}: {err.decode('utf-8')}")
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
        logger.error(f"sqlmap process for {target_url} timed out")

def run_nikto(target_url):
    logger.info(f"Running nikto for {target_url}...")
    nikto_command = f"nikto -h {target_url} -output ./nikto_output_{target_url.replace('https://', '').replace('/', '_')}.txt"
    process = subprocess.Popen(nikto_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = process.communicate(timeout=600)  # 10-minute timeout
        logger.info(f"nikto output for {target_url}: {out.decode('utf-8')}")
        if err:
            logger.error(f"nikto error for {target_url}: {err.decode('utf-8')}")
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
        logger.error(f"nikto process for {target_url} timed out")

def run_w3af(target_url):
    logger.info(f"Running w3af for {target_url}...")
    w3af_command = f"w3af_console -s w3af_script.w3af"
    script_content = f"""
plugins
    output console
    output text_file
    output config text_file
    set output_file ./w3af_output_{target_url.replace('https://', '').replace('/', '_')}.txt
    back

target
    set target {target_url}
    back

start
exit
"""
    with open('w3af_script.w3af', 'w') as script_file:
        script_file.write(script_content)
    process = subprocess.Popen(w3af_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = process.communicate(timeout=600)  # 10-minute timeout
        logger.info(f"w3af output for {target_url}: {out.decode('utf-8')}")
        if err:
            logger.error(f"w3af error for {target_url}: {err.decode('utf-8')}")
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
        logger.error(f"w3af process for {target_url} timed out")
    os.remove('w3af_script.w3af')

def run_wpscan(target_url):
    logger.info(f"Running wpscan for {target_url}...")
    wpscan_command = f"wpscan --url {target_url} --no-banner"
    process = subprocess.Popen(wpscan_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = process.communicate(timeout=600)  # 10-minute timeout
        logger.info(f"wpscan output for {target_url}: {out.decode('utf-8')}")
        if err:
            logger.error(f"wpscan error for {target_url}: {err.decode('utf-8')}")
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
        logger.error(f"wpscan process for {target_url} timed out")

def test_waf():
    logger.info("Starting WAF testing cycle...")
    start_zap()
    if check_zap_status():
        for target_url in TARGET_URLS:
            run_zap_scan(target_url)
            fetch_zap_results(target_url)
            run_sqlmap(target_url)
            run_nikto(target_url)
            run_w3af(target_url)
            run_wpscan(target_url)
        zap.core.shutdown()
        logger.info("Completed WAF testing cycle")
    else:
        logger.error("Skipping scans as ZAP is not running")

# Schedule the WAF test to run every 10 minutes (adjust as needed)
schedule.every(10).minutes.do(test_waf)

# Immediate call to test_waf for debugging purposes
test_waf()

try:
    logger.info("Starting WAF testing script...")
    while True:
        schedule.run_pending()
        time.sleep(1)
except KeyboardInterrupt:
    logger.info("Stopping WAF testing script...")
