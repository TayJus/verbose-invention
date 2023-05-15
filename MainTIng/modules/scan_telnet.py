import telnetlib

def scan_telnet(target):
    vulnerabilities = []
    try:
        tn = telnetlib.Telnet(target)
        tn.write(b'ls\n')
        tn.read_all()
        tn.close()
    except ConnectionRefusedError:
        vulnerabilities.append({'type': 'Telnet vulnerability', 'details': 'Connection refused.'})
    except Exception as e:
        vulnerabilities.append({'type': 'Telnet vulnerability', 'details': str(e)})
    return vulnerabilities