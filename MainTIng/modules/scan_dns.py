import logging
import socket

def scan_dns(target):
    try:
        logging.info('Resolving DNS...')
        socket.gethostbyname(target)
        logging.info('DNS resolution successful.')
        return True
    except socket.gaierror:
        logging.info('DNS resolution failed.')
        return False