import logging
import socket

def scan_voip(target):
    logging.info('Checking for open SIP port...')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((target, 5060))
        s.shutdown(socket.SHUT_RDWR)
        logging.info('Open SIP port found.')
        return True
    except (ConnectionRefusedError, socket.timeout):
        logging.info('No open SIP port found.')
        return False
    finally:
        s.close()