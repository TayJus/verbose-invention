import argparse
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from random import choice, randint
from string import ascii_letters, digits

import nmap
import requests
import sqlite3
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from sqlmap import SqlmapAPI

# Import custom modules.
from modules.database import scan_database
from modules.ftp import scan_ftp
from modules.smtp import scan_smtp
from modules.ssh import scan_ssh
from modules.telnet import scan_telnet
from modules.smb import scan_smb
from modules.dns import scan_dns
from modules.voip import scan_voip
import sys
sys.path.append('./modules')

# Set up logging.
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

# Set up argparse.
parser = argparse.ArgumentParser(description='ProteusProbe: A powerful vulnerability scanner.')
parser.add_argument('target', type=str, help='Target IP address or hostname.')
parser.add_argument('modules', nargs='+', choices=['ports', 'web', 'database', 'ftp', 'smtp', 'ssh', 'telnet', 'smb', 'dns', 'voip'], help='Modules to run.')
parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output.')
parser.add_argument('--output-dir', '-o', type=str, default=f'proteusprobe_output_{datetime.now().strftime("%Y%m%d_%H%M%S")}', help='Output directory.')
parser.add_argument('--license-key', '-l', type=str, help='License key.')
parser.add_argument('--generate-license', '-g', action='store_true', help='Generate a new license key.')
args = parser.parse_args()

# Set up variables.
target = args.target
modules = args.modules
verbose = args.verbose
output_dir = Path(args.output_dir)

# Set up the nmap scanner.
nm = nmap.PortScanner()

# Set up the SQLmap API.
sqlmap_api = SqlmapAPI()

# Set up the Selenium webdriver.
chrome_options = Options()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--disable-gpu')
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-dev-shm-usage')
chrome_driver_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'chromedriver')
driver = webdriver.Chrome(executable_path=chrome_driver_path, options=chrome_options)


# Define the license key generator.
def generate_license():
    license_key = ''.join(randint(0, 9) if i % 2 == 0 else choice(ascii_letters) for i in range(25))
    expiration_date = datetime.now() + timedelta(days=14)
    return license_key, expiration_date


# Define the license key checker.
def check_license(license_key):
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    c.execute('SELECT expiration_date FROM licenses WHERE license_key = ?', (license_key,))
    result = c.fetchone()
    conn.close()
    if result is None:
        return False
    expiration_date = datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S.%f')
    return datetime.now() <= expiration_date


# Display the welcome message and ask for the license key.
if args.license_key:
    if check_license(args.license_key):
        logging.info('License key accepted.')
    else:
        logging.info('Invalid license key.')
        sys.exit()
else:
    if args.generate_license:
        license_key, expiration_date = generate_license()
        logging.info(f'New license key generated: {license_key} (expires {expiration_date.strftime("%Y-%m-%d")}).')
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute('INSERT INTO licenses (license_key, expiration_date) VALUES (?, ?)', (license_key, expiration_date))
        conn.commit()
        conn.close()
    else:
        with open('ascii_art.txt', 'r') as f:
            logging.info(f.read())
        while True:
            license_key = input('Please enter your license key: ')
            if check_license(license_key):
                logging.info('License key accepted.')
                break
            else:
                logging.info('Invalid license key. Please try again.')


# Define the scan function.
def scan(target, modules):
    logging.info('Starting scan...')

    # Scan for open ports.
    if 'ports' in modules:
        logging.info('Scanning for open ports...')
        nm.scan(target, '1-65535')
        open_ports = [p for p in nm[target]['tcp'].keys() if nm[target]['tcp'][p]['state'] == 'open']
        logging.info(f'Open ports: {open_ports}')

        # Save the open ports to a file.
        with (output_dir / 'open_ports.txt').open('w') as f:
            f.write('\n'.join(str(p) for p in open_ports))

    # Scan for web vulnerabilities.
    if 'web' in modules:
        logging.info('Scanning for web vulnerabilities...')
        url = f'http://{target}'
        driver.get(url)
        page_source = driver.page_source
        vulnerabilities = []

        # Check for SQL injection.
        if 'database' in modules:
            logging.info('Checking for SQL injection...')
            sqlmap_api.scan(url=url)
            sqlmap_results = sqlmap_api.status()
            if sqlmap_results['status'] == 'running':
                time.sleep(5)
            sqlmap_results = sqlmap_api.status()
            if sqlmap_results['status'] == 'terminated' and sqlmap_results['success']:
                vulnerabilities.append('SQL injection')
                sqlmap_api.flush()
                logging.info('SQL injection found.')
            else:
                logging.info('No SQL injection found.')

        # Check for FTP vulnerabilities.
        if 'ftp' in modules:
            logging.info('Checking for FTP vulnerabilities...')
            ftp_vulnerabilities = scan_ftp(target)
            if ftp_vulnerabilities:
                vulnerabilities.append('FTP vulnerability')
                logging.info('FTP vulnerability found.')
            else:
                logging.info('No FTP vulnerability found.')

        # Check for SMTP vulnerabilities.
        if 'smtp' in modules:
            logging.info('Checking for SMTP vulnerabilities...')
            smtp_vulnerabilities = scan_smtp(target)
            if smtp_vulnerabilities:
                vulnerabilities.append('SMTP vulnerability')
                logging.info('SMTP vulnerability found.')
            else:
                logging.info('No SMTP vulnerability found.')

        # Check for SSH vulnerabilities.
        if 'ssh' in modules:
            logging.info('Checking for SSH vulnerabilities...')
            ssh_vulnerabilities = scan_ssh(target)
            if ssh_vulnerabilities:
                vulnerabilities.append('SSH vulnerability')
                logging.info('SSH vulnerability found.')
            else:
                logging.info('No SSH vulnerability found.')

        # Check for Telnet vulnerabilities.
        if 'telnet' in modules:
            logging.info('Checking for Telnet vulnerabilities...')
            telnet_vulnerabilities = scan_telnet(target)
            if telnet_vulnerabilities:
                vulnerabilities.append('Telnet vulnerability')
                logging.info('Telnet vulnerability found.')
            else:
                logging.info('No Telnet vulnerability found.')

        # Check for SMB vulnerabilities.
        if 'smb' in modules:
            logging.info('Checking for SMB vulnerabilities...')
            smb_vulnerabilities = scan_smb(target)
            if smb_vulnerabilities:
                vulnerabilities.append('SMB vulnerability')
                logging.info('SMB vulnerability found.')
            else:
                logging.info('No SMB vulnerability found.')

        # Check for DNS vulnerabilities.
        if 'dns' in modules:
            logging.info('Checking for DNS vulnerabilities...')
            dns_vulnerabilities = scan_dns(target)
            if dns_vulnerabilities:
                vulnerabilities.append('DNS vulnerability')
                logging.info('DNS vulnerability found.')
            else:
                logging.info('No DNS vulnerability found.')

        # Check for VoIP vulnerabilities.
        if 'voip' in modules:
            logging.info('Checking for VoIP vulnerabilities...')
            voip_vulnerabilities = scan_voip(target)
            if voip_vulnerabilities:
                vulnerabilities.append('VoIP vulnerability')
                logging.info('VoIP vulnerability found.')
            else:
                logging.info('No VoIP vulnerability found.')

        # Save the vulnerabilities to a file.
        if vulnerabilities:
            with (output_dir / 'vulnerabilities.txt').open('w') as f:
                f.write('\n'.join(vulnerabilities))
        else:
            with (output_dir / 'vulnerabilities.txt').open('w') as f:
                f.write('No vulnerabilities found.')

    logging.info('Scan complete.')


# Run the scan.
scan(target, modules)