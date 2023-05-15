import logging
import os
import socket

import smbclient

def scan_smb(target):
    try:
        logging.info('Connecting to SMB...')
        smbclient.register_session(target, username='', password='')
        logging.info('SMB connection successful.')
        return True
    except smbclient.SMBConnectionError:
        logging.info('SMB connection failed.')
        return False