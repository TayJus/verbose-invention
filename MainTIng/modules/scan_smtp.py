import smtplib

def scan_smtp(target):
    vulnerabilities = []
    try:
        smtp = smtplib.SMTP(target)
        smtp.noop()
        smtp.quit()
    except smtplib.SMTPServerDisconnected:
        vulnerabilities.append({'type': 'SMTP vulnerability', 'details': 'Server disconnected.'})
    except smtplib.SMTPConnectError:
        vulnerabilities.append({'type': 'SMTP vulnerability', 'details': 'Connection error.'})
    except smtplib.SMTPAuthenticationError:
        vulnerabilities.append({'type': 'SMTP vulnerability', 'details': 'Authentication error.'})
    except smtplib.SMTPHeloError:
        vulnerabilities.append({'type': 'SMTP vulnerability', 'details': 'HELO error.'})
    except smtplib.SMTPException as e:
        vulnerabilities.append({'type': 'SMTP vulnerability', 'details': str(e)})
    return vulnerabilities