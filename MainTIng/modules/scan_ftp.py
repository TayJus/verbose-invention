import ftplib

def scan_ftp(target):
    vulnerabilities = []
    try:
        ftp = ftplib.FTP(target)
        ftp.login()
        ftp.retrlines('LIST')
        ftp.quit()
    except ftplib.all_errors as e:
        vulnerabilities.append({'type': 'FTP vulnerability', 'details': str(e)})
    return vulnerabilities